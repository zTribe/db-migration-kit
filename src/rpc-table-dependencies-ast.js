/**
 * PostgreSQL AST-based table dependency audit.
 *
 * No keyword-based FROM/JOIN/INTO scanning. The SQL AST enumerates RangeVar
 * nodes and schema-qualified FuncCall nodes. PL/pgSQL statements are traversed
 * using libpg_query's PL/pgSQL AST, with inner SQL parsed separately.
 *
 * This module is deliberately advisory: parser PG major version 18 differs
 * from the target PG17 server. Even zero warnings cannot prove complete
 * semantic/indirect dependencies (views, triggers, overloaded SQL, search_path).
 */
import { parse, parsePlPgSQL } from "libpg-query";

const qualified = x => /^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/i.test(x);
const norm = x => x.toLowerCase();
const unique = xs => [...new Set(xs)].sort();
function nstr(x){
  return x?.String?.sval ?? x?.String?.str ?? x?.sval ?? null;
}
function readName(parts){
  if(!Array.isArray(parts))return null;
  const p=parts.map(nstr);
  return p.length === 2 && p.every(x=>typeof x==="string")? p.join(".").toLowerCase():null;
}
/** Extract schema-qualified relations and function calls from parsed SQL. */
function walkSqlTree(tree,tables,calls,warnings){
  if(!tree||typeof tree!=="object")return;
  if(Array.isArray(tree)){for(const x of tree)walkSqlTree(x,tables,calls,warnings);return;}
  function relation(r){
    if(!r||typeof r.relname!=="string"){warnings.add("unsupported-relation-node");return;}
    if(typeof r.schemaname==="string")tables.add(norm(r.schemaname+"."+r.relname));
    else warnings.add("unqualified-relation:"+r.relname);
  }
  if(tree.RangeVar)relation(tree.RangeVar);
  // libpg_query represents DML targets as bare relation objects, unlike
  // FROM/JOIN expression nodes wrapped in RangeVar.
  for(const kind of ["InsertStmt","UpdateStmt","DeleteStmt","MergeStmt"]){
    if(tree[kind])relation(tree[kind].relation);
  }
  if(tree.FuncCall){
    const fn=readName(tree.FuncCall.funcname);
    if(fn&&!fn.startsWith("pg_catalog.")&&!fn.startsWith("information_schema."))calls.add(fn);
  }
  if(tree.CreateStmt||tree.CreateFunctionStmt||tree.AlterTableStmt||tree.ViewStmt||tree.CreateTrigStmt){
    warnings.add("unsupported-sql-statement");
  }
  for(const [key,value] of Object.entries(tree)){
    if(key==="location"||key==="stmt_location"||key==="stmt_len")continue;
    walkSqlTree(value,tables,calls,warnings);
  }
}
async function parseSql(query,tables,calls,warnings,mode=0){
  let tree;
  try {
    tree=await parse(query);
  } catch(error) {
    // PL/pgSQL stores expression-mode nodes without their implicit SELECT.
    // This fallback is still parsed by PostgreSQL, never scanned as text.
    if(mode===2) {
      try { tree=await parse("SELECT "+query); }
      catch(e) { warnings.add("unparsed-expression:"+String(e?.message||e).slice(0,100)); return; }
    } else {
      warnings.add("unparsed-sql:"+String(error?.message||error).slice(0,100));
      return;
    }
  }
  if(!Array.isArray(tree?.stmts)){warnings.add("missing-parse-tree-statements");return;}
  walkSqlTree(tree.stmts,tables,calls,warnings);
}
/** Walk a parsed PL/pgSQL AST, never treating arbitrary text as SQL. */
async function walkPlpgsql(tree,tables,calls,warnings){
  if(!tree||typeof tree!=="object")return;
  if(Array.isArray(tree)){for(const x of tree)await walkPlpgsql(x,tables,calls,warnings);return;}
  if(tree.PLpgSQL_expr){
    const expr=tree.PLpgSQL_expr;
    if(typeof expr.query==="string")await parseSql(expr.query,tables,calls,warnings,expr.parseMode??0);
    else warnings.add("plpgsql-expression-without-sql");
    return;
  }
  // PL/pgSQL dynamic EXECUTE cannot be statically determined.
  if(tree.PLpgSQL_stmt_dynexecute||tree.PLpgSQL_stmt_dynfors){
    warnings.add("dynamic-plpgsql-sql");
    return;
  }
  for(const [key,value] of Object.entries(tree)){
    if(key==="datums")continue;
    await walkPlpgsql(value,tables,calls,warnings);
  }
}
async function analyzeFunction(fn){
  const tables=new Set(), calls=new Set(),warnings=new Set();
  const definition=fn.definition;
  if(typeof definition!=="string"||!definition.trim()){
    warnings.add("missing-function-definition");
    return {tables:[],calls:[],warnings:[...warnings]};
  }
  // pg_get_functiondef is authoritative about language and body. Parse
  // PL/pgSQL using its own parser instead of splitting on semicolons.
  if(/\bLANGUAGE\s+plpgsql\b/i.test(definition)){
    try{
      const ast=await parsePlPgSQL(definition);
      const funcs=Array.isArray(ast)?ast:ast?.plpgsql_funcs;
      if(!Array.isArray(funcs)||!funcs.length)throw Error("missing PLpgSQL funcs");
      await walkPlpgsql(funcs,tables,calls,warnings);
    }catch(e){warnings.add("unparsed-plpgsql:"+String(e?.message||e).slice(0,120));}
  }else if(/\bLANGUAGE\s+sql\b/i.test(definition)){
    // AST parsing of CREATE FUNCTION does not recursively parse its
    // string-literal body. The delimiter regex ONLY locates the body.
    const m=/\bAS\s+(\$[a-z_0-9]*\$)([\s\S]*?)\1/i.exec(definition);
    if(!m)warnings.add("unrecognized-sql-function-body");
    else await parseSql(m[2],tables,calls,warnings);
  }else{
    warnings.add("unsupported-language");
  }
  return {tables:unique([...tables]),calls:unique([...calls]),warnings:unique([...warnings])};
}
/**
 * contracts: [{id:"api.function",tables:["chain.tokens"]}]
 * WARNING: advisory only, cannot authorize database/Redis release.
 */
export async function auditRpcTableDependenciesAst(snapshot,contracts){
  if(!Array.isArray(snapshot?.functions))throw Error("AST audit: catalog.functions is required");
  if(!Array.isArray(contracts)||!contracts.length)throw Error("AST audit: contracts required");
  const catalog=new Map();
  for(const fn of snapshot.functions){
    const id=norm(fn.schema_name+"."+fn.name);
    if(!catalog.has(id))catalog.set(id,[]);
    catalog.get(id).push(fn);
  }
  const memo=new Map();
  async function visit(fn,stack=new Set()){
    const id=norm(fn.schema_name+"."+fn.name);
    if(memo.has(id))return memo.get(id);
    if(stack.has(id))return {tables:[],warnings:["recursive-call:"+id]};
    const direct=await analyzeFunction(fn);
    const tables=[...direct.tables],warnings=[...direct.warnings];
    for(const callee of direct.calls){
      const matches=catalog.get(callee)||[];
      if(matches.length!==1){warnings.push("unresolved-or-overloaded-call:"+callee);continue;}
      const nested=await visit(matches[0],new Set([...stack,id]));
      tables.push(...nested.tables);
      warnings.push(...nested.warnings.map(x=>"via-"+callee+":"+x));
    }
    const result={tables:unique(tables),warnings:unique(warnings)};
    memo.set(id,result);return result;
  }
  const seen=new Set(),results=[];
  for(const c of contracts){
    const id=norm(String(c?.id??""));
    if(!qualified(id)||seen.has(id))throw Error("AST audit: invalid or duplicate contract RPC");
    seen.add(id);
    if(!Array.isArray(c.tables)||c.tables.some(x=>typeof x!=="string"||!qualified(x)))throw Error("AST audit: invalid tables");
    const declared=unique(c.tables.map(norm));
    if(declared.length!==c.tables.length)throw Error("AST audit: duplicate table");
    const matches=catalog.get(id)||[];
    if(matches.length!==1){
      results.push({id,actualTables:[],missing:[],stale:declared,warnings:["missing-or-overloaded-rpc"],requiresReview:true});
      continue;
    }
    const actual=await visit(matches[0]);
    const missing=actual.tables.filter(x=>!declared.includes(x));
    const stale=declared.filter(x=>!actual.tables.includes(x));
    results.push({id,actualTables:actual.tables,missing,stale,warnings:actual.warnings,
      requiresReview:missing.length>0||stale.length>0||actual.warnings.length>0});
  }
  return {results,requiresReview:results.some(x=>x.requiresReview),releaseApproved:false,
    dependencyGraphComplete:false,parserFamily:"libpg-query",parserMajor:18,targetPostgresMajor:17,
    warnings:["AST syntax evidence only; parser is PG18 on PG17 catalogs; no automatic approval.","Views, triggers, implicit dependencies, dynamic SQL and semantic/Redis compatibility need separate verification."]};
}
