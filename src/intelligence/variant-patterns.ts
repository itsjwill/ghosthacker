// Copyright (C) 2026 Ghost Hacker Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CVE Variant Pattern Database
 *
 * Structured patterns for known vulnerability classes, extracted from
 * high-impact web application CVEs. The Variant Hunter agent uses these
 * patterns to find similar-but-different vulnerabilities in target codebases.
 *
 * Inspired by Google's Big Sleep project which found real zero-days
 * using variant analysis.
 */

export interface VariantPattern {
  id: string;
  cve_examples: string[];          // e.g., ["CVE-2023-32784", "CVE-2024-12345"]
  vuln_class: string;              // e.g., "path-traversal", "prototype-pollution"
  description: string;
  root_cause: string;              // What makes this vulnerability exist
  code_patterns: CodePattern[];    // What to look for in source code
  tech_stacks: string[];           // Where this pattern is commonly found
  severity: 'critical' | 'high' | 'medium';
  exploitation_hint: string;       // How to verify if the variant is exploitable
}

export interface CodePattern {
  name: string;
  description: string;
  search_terms: string[];          // Strings/patterns to grep for
  dangerous_constructs: string[];  // Code constructs that indicate vulnerability
  safe_alternatives: string[];     // What the secure version looks like
}

/**
 * Core vulnerability variant patterns derived from top web app CVEs
 */
export const VARIANT_PATTERNS: readonly VariantPattern[] = Object.freeze([
  {
    id: 'path-traversal-file-ops',
    cve_examples: ['CVE-2023-32784', 'CVE-2021-41773', 'CVE-2024-23897'],
    vuln_class: 'path-traversal',
    description: 'User-controlled input used in file path construction without proper sanitization, allowing directory traversal to read/write arbitrary files.',
    root_cause: 'Concatenating user input into file paths without normalizing or validating against a whitelist. Path.join does NOT prevent traversal.',
    code_patterns: [
      {
        name: 'Direct path concatenation',
        description: 'User input directly concatenated into file paths',
        search_terms: ['path.join', 'path.resolve', 'fs.readFile', 'fs.writeFile', 'fs.createReadStream', 'open(', 'file_get_contents', 'fopen'],
        dangerous_constructs: [
          'path.join(baseDir, req.params.filename)',
          'path.join(uploadDir, userInput)',
          'fs.readFile(req.query.file)',
          'open(os.path.join(base, user_input))',
        ],
        safe_alternatives: [
          'path.resolve() + startsWith check against allowed directory',
          'Whitelist of allowed filenames',
          'Strip all path separators from input',
        ],
      },
      {
        name: 'Incomplete traversal filtering',
        description: 'Filters ../ but not encoded variants',
        search_terms: ['replace(../', 'replace("../",', 'str_replace("../",', 'replaceAll("../",'],
        dangerous_constructs: [
          'input.replace("../", "")',  // Doesn't handle .../ or encoded variants
          'input.replaceAll("../", "")',  // Vulnerable to ....// bypass
        ],
        safe_alternatives: [
          'path.resolve() then verify result starts with intended directory',
          'Use realpath() then compare to allowed base',
        ],
      },
    ],
    tech_stacks: ['node', 'express', 'python', 'django', 'flask', 'php', 'java', 'spring'],
    severity: 'high',
    exploitation_hint: 'Try ../../etc/passwd, ..%2f..%2fetc%2fpasswd, and ..\\..\\windows\\win.ini to verify traversal.',
  },
  {
    id: 'prototype-pollution',
    cve_examples: ['CVE-2022-24999', 'CVE-2021-25945', 'CVE-2020-28469'],
    vuln_class: 'prototype-pollution',
    description: 'User-controlled object keys can modify JavaScript object prototypes via __proto__, constructor.prototype, or merge operations.',
    root_cause: 'Recursive merge/assign operations that don\'t filter prototype-unsafe keys (__proto__, constructor, prototype).',
    code_patterns: [
      {
        name: 'Unsafe deep merge',
        description: 'Recursive object merge without prototype key filtering',
        search_terms: ['Object.assign', 'lodash.merge', '_.merge', 'deepMerge', 'extend(', 'Object.keys(', 'for (let key in'],
        dangerous_constructs: [
          'Object.assign(target, untrustedSource)',
          '_.merge({}, untrustedInput)',
          'for (const key in userObj) { target[key] = userObj[key]; }',
        ],
        safe_alternatives: [
          'Filter __proto__, constructor, prototype keys before merge',
          'Use Object.create(null) for dictionaries',
          'Use Map instead of plain objects for user data',
        ],
      },
    ],
    tech_stacks: ['node', 'express', 'javascript', 'typescript'],
    severity: 'critical',
    exploitation_hint: 'Send {"__proto__": {"isAdmin": true}} in JSON body and check if Object.prototype.isAdmin becomes true.',
  },
  {
    id: 'nosql-injection',
    cve_examples: ['CVE-2021-22911', 'CVE-2019-2729'],
    vuln_class: 'nosql-injection',
    description: 'User input passed as MongoDB query operators ($gt, $ne, $regex) allowing query manipulation.',
    root_cause: 'Passing unvalidated req.body directly to MongoDB query methods without type checking or operator stripping.',
    code_patterns: [
      {
        name: 'Direct query parameter injection',
        description: 'Request body/params passed directly to MongoDB find/update',
        search_terms: ['.find(', '.findOne(', '.updateOne(', '.deleteOne(', 'collection.', 'req.body', 'req.query'],
        dangerous_constructs: [
          'db.collection.find({ email: req.body.email, password: req.body.password })',
          'Model.findOne(req.query)',
          'collection.updateOne({ _id: req.params.id }, { $set: req.body })',
        ],
        safe_alternatives: [
          'Validate input types (typeof password === "string")',
          'Use mongo-sanitize to strip $ operators',
          'Explicitly extract fields instead of passing whole body',
        ],
      },
    ],
    tech_stacks: ['node', 'express', 'mongodb', 'mongoose'],
    severity: 'critical',
    exploitation_hint: 'Send {"password": {"$ne": ""}} in login to bypass authentication, or {"$regex": "^a"} for data extraction.',
  },
  {
    id: 'ssti-template-injection',
    cve_examples: ['CVE-2023-46604', 'CVE-2019-11581'],
    vuln_class: 'server-side-template-injection',
    description: 'User input rendered directly in server-side templates without escaping, allowing code execution.',
    root_cause: 'Passing user input as template string instead of template variable. The input becomes part of the template itself.',
    code_patterns: [
      {
        name: 'String concatenation in templates',
        description: 'User input concatenated into template strings',
        search_terms: ['render_template_string', 'Template(', 'Jinja2', 'nunjucks', 'ejs.render', 'pug.render', 'Handlebars.compile'],
        dangerous_constructs: [
          'render_template_string("Hello " + user_input)',
          'Template(user_input).render()',
          'ejs.render(userTemplate, data)',
          'nunjucks.renderString(req.body.template, {})',
        ],
        safe_alternatives: [
          'render_template("hello.html", name=user_input)',
          'Use template variables, never concatenate input into template source',
          'Sandbox template rendering with restricted globals',
        ],
      },
    ],
    tech_stacks: ['python', 'flask', 'jinja2', 'django', 'node', 'express', 'ejs', 'nunjucks', 'java', 'freemarker', 'thymeleaf'],
    severity: 'critical',
    exploitation_hint: 'Send {{7*7}} or ${7*7} — if 49 appears in response, SSTI is confirmed. Then escalate to RCE.',
  },
  {
    id: 'deserialization-rce',
    cve_examples: ['CVE-2023-2255', 'CVE-2022-22965', 'CVE-2021-22986'],
    vuln_class: 'insecure-deserialization',
    description: 'Application deserializes untrusted data, allowing object injection and potentially remote code execution.',
    root_cause: 'Using language-native deserialization (pickle, java serialization, PHP unserialize) on untrusted input without type validation.',
    code_patterns: [
      {
        name: 'Unsafe deserialization',
        description: 'Language-native deserialization of untrusted data',
        search_terms: ['pickle.loads', 'yaml.load', 'unserialize(', 'ObjectInputStream', 'readObject(', 'JSON.parse', 'eval(', 'Function('],
        dangerous_constructs: [
          'pickle.loads(request.data)',
          'yaml.load(user_input)  # yaml.safe_load is safe',
          'unserialize($_POST["data"])',
          'new ObjectInputStream(untrustedStream).readObject()',
        ],
        safe_alternatives: [
          'Use JSON instead of pickle/yaml',
          'yaml.safe_load() instead of yaml.load()',
          'Validate class types before deserialization',
          'Use allowlists for deserializable classes',
        ],
      },
    ],
    tech_stacks: ['python', 'java', 'php', 'ruby', 'node'],
    severity: 'critical',
    exploitation_hint: 'For Python pickle: craft payload with __reduce__ method. For Java: use ysoserial gadget chains.',
  },
  {
    id: 'race-condition-toctou',
    cve_examples: ['CVE-2023-38408', 'CVE-2022-29217'],
    vuln_class: 'race-condition',
    description: 'Time-of-check to time-of-use (TOCTOU) race condition allowing privilege escalation or double-spend.',
    root_cause: 'Checking a condition (balance, permission, existence) and then acting on it in separate operations without atomic locking.',
    code_patterns: [
      {
        name: 'Non-atomic check-then-act',
        description: 'Permission/balance check separated from the action by time',
        search_terms: ['if (balance', 'if (user.isAdmin', 'if (await', 'findOne', 'then update', 'check.*then'],
        dangerous_constructs: [
          'if (balance >= amount) { balance -= amount; }  // Not atomic',
          'const user = await User.findOne(id); if (user.isAdmin) { grantAccess(); }',
          'if (fs.existsSync(file)) { fs.unlinkSync(file); }',
        ],
        safe_alternatives: [
          'Use database transactions with row-level locking',
          'Use atomic operations (findOneAndUpdate with conditions)',
          'Use optimistic concurrency control (version field)',
          'Use mutex/semaphore for critical sections',
        ],
      },
    ],
    tech_stacks: ['node', 'python', 'java', 'go', 'ruby'],
    severity: 'high',
    exploitation_hint: 'Send concurrent requests (10+) to the same endpoint simultaneously. Check for double-spend, duplicate creation, or privilege escalation.',
  },
  {
    id: 'mass-assignment',
    cve_examples: ['CVE-2023-28432', 'CVE-2012-2661'],
    vuln_class: 'mass-assignment',
    description: 'Application allows users to set model attributes that should be protected (isAdmin, role, verified) by passing extra fields.',
    root_cause: 'Binding HTTP request body directly to ORM model without specifying allowed fields.',
    code_patterns: [
      {
        name: 'Direct model binding',
        description: 'Request body directly used to create/update model',
        search_terms: ['Model.create(req.body', 'new Model(req.body', '.update(req.body', 'Object.assign(user, req.body', 'User.build(req.body'],
        dangerous_constructs: [
          'User.create(req.body)',
          'user.update(req.body)',
          'Object.assign(user, req.body)',
          'new User({...req.body})',
        ],
        safe_alternatives: [
          'Extract only allowed fields: { name: req.body.name, email: req.body.email }',
          'Use DTOs (Data Transfer Objects) with explicit field lists',
          'ORM-level attribute protection (attr_accessible, fillable)',
        ],
      },
    ],
    tech_stacks: ['node', 'express', 'rails', 'django', 'laravel', 'spring'],
    severity: 'high',
    exploitation_hint: 'Add extra fields to registration/update: {"name":"test","email":"test@test.com","role":"admin","isAdmin":true}',
  },
  {
    id: 'jwt-vulnerabilities',
    cve_examples: ['CVE-2022-23529', 'CVE-2018-0114'],
    vuln_class: 'jwt-security',
    description: 'JWT implementation flaws allowing token forgery via algorithm confusion, weak secrets, or missing validation.',
    root_cause: 'Not validating JWT algorithm, using weak symmetric secrets, or trusting claims without verification.',
    code_patterns: [
      {
        name: 'Algorithm confusion / none algorithm',
        description: 'JWT verification accepts attacker-controlled algorithm',
        search_terms: ['jwt.verify', 'jwt.decode', 'jsonwebtoken', 'jose', 'JWT', 'algorithms'],
        dangerous_constructs: [
          'jwt.verify(token, secret)  // No algorithms restriction',
          'jwt.decode(token)  // Decode without verification',
          'jwt.verify(token, publicKey, { algorithms: ["RS256", "HS256"] })  // Algorithm confusion',
        ],
        safe_alternatives: [
          'jwt.verify(token, secret, { algorithms: ["HS256"] })  // Explicit algorithm',
          'Never use jwt.decode() for authentication decisions',
          'Use asymmetric (RS256) instead of symmetric (HS256) when possible',
        ],
      },
    ],
    tech_stacks: ['node', 'express', 'python', 'flask', 'django', 'java', 'spring'],
    severity: 'critical',
    exploitation_hint: 'Try: (1) Change alg to "none", remove signature; (2) Change alg from RS256 to HS256, sign with public key; (3) Brute-force weak HS256 secrets.',
  },
]);

/**
 * Get patterns relevant to a specific tech stack
 */
export function getPatternsForStack(techStack: Partial<{ language: string; framework: string; database: string }>): VariantPattern[] {
  return VARIANT_PATTERNS.filter(pattern => {
    const stacks = pattern.tech_stacks;
    if (techStack.language && stacks.includes(techStack.language)) return true;
    if (techStack.framework && stacks.includes(techStack.framework)) return true;
    if (techStack.database && stacks.includes(techStack.database)) return true;
    return false;
  });
}

/**
 * Get all pattern search terms for a vulnerability class
 */
export function getSearchTerms(vulnClass: string): string[] {
  const pattern = VARIANT_PATTERNS.find(p => p.vuln_class === vulnClass);
  if (!pattern) return [];
  return pattern.code_patterns.flatMap(cp => cp.search_terms);
}
