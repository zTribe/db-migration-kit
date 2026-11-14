// Consume comments and quoted bodies before inspecting statement starts.
const tokens = /\s+|--[^\r\n]*|\/\*|[eE]'(?:\\[\s\S]|''|[^'\\])*'|'(?:''|[^'])*'|"(?:""|[^"])*"|\$(?:[a-z_][a-z_0-9]*)?\$|[a-z_\u0080-\uffff][a-z_0-9$\u0080-\uffff]*|./gisy;
const forbidden = /^(BEGIN|START|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE)$/i;

export function assertManagedTransaction(sql, version) {
  const scanner = new RegExp(tokens.source, tokens.flags);
  let first = "";
  while (scanner.lastIndex < sql.length) {
    const [token] = scanner.exec(sql);
    if (token === "/*") {
      let depth = 1;
      const comments = /\/\*|\*\//g;
      comments.lastIndex = scanner.lastIndex;
      while (depth) {
        const match = comments.exec(sql);
        if (!match) throw new Error(`Unclosed SQL comment: ${version}`);
        depth += match[0] === "/*" ? 1 : -1;
      }
      scanner.lastIndex = comments.lastIndex;
      continue;
    }
    if (/^\s|^--/.test(token)) continue;
    if (token === ";") {
      first = "";
      continue;
    }
    if (!first && forbidden.test(token) ||
        first === "PREPARE" && /^TRANSACTION$/i.test(token) ||
        first === "SET" && /^TRANSACTION$/i.test(token)) {
      throw new Error(`Migration must leave transaction control to Kit: ${version}`);
    }
    first = first ? "-" : token.toUpperCase();
    if (/^\$.+\$$|^\$\$$/.test(token)) {
      const end = sql.indexOf(token, scanner.lastIndex);
      if (end === -1) throw new Error(`Unclosed SQL body: ${version}`);
      scanner.lastIndex = end + token.length;
    }
  }
}
