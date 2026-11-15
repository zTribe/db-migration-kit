/**
 * Conservative review gate for direct SQL table references in live PostgreSQL
 * pg_get_functiondef() output. This is NOT an SQL AST or complete dependency
 * graph; dynamic SQL, ambiguous calls, unqualified relations and unsupported
 * bodies must be reviewed rather than approved.
 */
const IDENT=/^[a-z_][a-z0-9_]*$/i;
const normalize=name=>name.toLowerCase();
const unique=items=>[...new Set(items)].sort();

function bodyOf(definition){
  const match=/\bAS\s+(\$[a-z_0-9]*\$)([\s\S]*?)\1/i.exec(definition);
  return match?.[2]??null;
}
function stripLiterals(sql){
  // Preserve token positions sufficiently for conservative lexical matching.
  return sql
    .replace(/\/\*[\s\S]*?\*\//g," ")
    .replace(/--[^\n]*/g," ")
    .replace(/'(?:''|[^'])*'/g,"''");
}
function directReferences(fn){
  const warnings=[],tables=[],calls=[];
  const body=bodyOf(fn.definition||"");
  if(body===null)return {tables:[],calls:[],warnings:["unsupported-function-body"]};
  if(/\bEXECUTE\b|\bformat\s*\(|\bquote_ident\s*\(/i.test(body)) warnings.push("dynamic-sql-or-identifier");
  // PostgreSQL EXTRACT(field FROM expression) uses FROM as a keyword but
  // has no relation operand. Mask these clauses before lexical relation scan.
  // Complex expressions not recognized here remain subject to manual review.
  const sql=stripLiterals(body).replace(/\bEXTRACT\s*\(\s*[a-z_][\w]*\s+FROM\s+[a-z_][\w]*\s*\)/gi,"EXTRACT_VALUE");
  // Named relation references in common DML forms, including subqueries and JOINs.
  const relation=/\b(?:FROM|JOIN|UPDATE(?!\s+SET\b)|INSERT\s+INTO|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(?:ONLY\s+)?((?:"?[a-z_][\w]*"?)(?:\s*\.\s*"?[a-z_][\w]*"?)?)/gi;
  for(const match of sql.matchAll(relation)){
    const end=match.index+match[0].length;
    const name=match[1].replaceAll('"',"").replace(/\s+/g,"").toLowerCase();
    if(sql.slice(end).trimStart().startsWith("(")) continue; // set-returning function, not a table
    if(!name.includes(".")){
      if(!["select","values","lateral"].includes(name)) warnings.push("unqualified-relation:"+name);
    }else{
      const [schema,table]=name.split(".");
      if(IDENT.test(schema)&&IDENT.test(table)) tables.push(name);
      else warnings.push("invalid-relation:"+name);
    }
  }
  // Explicit calls into non-system schemas require transitive analysis.
  const call=/\b([a-z_][\w]*)\.([a-z_][\w]*)\s*\(/gi;
  for(const m of sql.matchAll(call)){
    // INSERT INTO schema.table(column_list) is a relation plus column list,
    // not a function call. Keep SQL table-valued functions reviewable.
    if(/\bINSERT\s+INTO\s*$/i.test(sql.slice(Math.max(0,m.index-40),m.index)))continue;
    const schema=normalize(m[1]);
    if(!["pg_catalog","information_schema"].includes(schema)) calls.push(schema+"."+normalize(m[2]));
  }
  return {tables:unique(tables),calls:unique(calls),warnings:unique(warnings)};
}
function fnName(fn){return (fn.schema_name+"."+fn.name).toLowerCase()}
function auditOne(fn,map,stack){
  const direct=directReferences(fn);
  const tables=[...direct.tables],warnings=[...direct.warnings];
  for(const call of direct.calls){
    if(call===fnName(fn)){warnings.push("recursive-call:"+call);continue}
    const matches=map.get(call)||[];
    if(matches.length!==1){warnings.push("unresolved-or-overloaded-call:"+call);continue}
    if(stack.has(call)){warnings.push("recursive-call:"+call);continue}
    const nested=auditOne(matches[0],map,new Set([...stack,call]));
    tables.push(...nested.tables);
    warnings.push(...nested.warnings.map(x=>"via-"+call+":"+x));
  }
  return {tables:unique(tables),warnings:unique(warnings)};
}

/**
 * contracts: [{ id: "api.fn", tables: ["chain.foo", ...] }]
 * Always returns releaseApproved:false: static scan is evidence, not certification.
 */
export function auditRpcTableDependencies(snapshot,contracts){
  if(!Array.isArray(snapshot?.functions))throw Error("RPC dependency audit: PostgreSQL catalog required");
  if(!Array.isArray(contracts)||!contracts.length)throw Error("RPC dependency audit: contracts required");
  const map=new Map();
  for(const fn of snapshot.functions){
    const id=fnName(fn);
    if(!map.has(id))map.set(id,[]);
    map.get(id).push(fn);
  }
  const seen=new Set(),results=[];
  for(const contract of contracts){
    const id=String(contract?.id??"").toLowerCase();
    if(!/^[a-z_]\w*\.[a-z_]\w*$/.test(id)||seen.has(id))throw Error("RPC dependency audit: invalid or duplicated function identifier");
    seen.add(id);
    if(!Array.isArray(contract.tables)||contract.tables.some(x=>typeof x!=="string"||!/^[a-z_]\w*\.[a-z_]\w*$/.test(x)))throw Error("RPC dependency audit: invalid declared tables");
    const declared=unique(contract.tables.map(normalize));
    if(declared.length!==contract.tables.length)throw Error("RPC dependency audit: duplicate tables");
    const matches=map.get(id)||[];
    if(matches.length!==1){
      results.push({id,missing:[],stale:[],warnings:["missing-or-overloaded-rpc"],requiresReview:true});
      continue;
    }
    const actual=auditOne(matches[0],map,new Set([id]));
    const missing=actual.tables.filter(x=>!declared.includes(x));
    const stale=declared.filter(x=>!actual.tables.includes(x));
    results.push({id,actualTables:actual.tables,missing,stale,warnings:actual.warnings,
      requiresReview:missing.length>0||stale.length>0||actual.warnings.length>0});
  }
  return {results,requiresReview:results.some(x=>x.requiresReview),releaseApproved:false,
    dependencyGraphComplete:false,
    warnings:["Conservative lexical evidence only. PostgreSQL pg_depend, views, triggers, dynamic SQL, unqualified names and data semantics require independent verification."]};
}
