// AI Jungle Badge 검증 로직 (Open Badges 3.0, VC-JWT/RS256).
// DOM을 쓰지 않아 브라우저와 Node(테스트) 양쪽에서 돌아간다. 외부 라이브러리 없이
// WebCrypto(RSASSA-PKCS1-v1_5)와 DecompressionStream만 쓴다.

const ITXT_KEYWORD = "openbadgecredential";
const JWT_ALG = "RS256"; // OB 3.0 §8.2.3 VC-JWT 필수 알고리즘 — 발급 측 aijbadge.issuing.ALGORITHM과 같아야 한다
const KEY_ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];

class BadgeError extends Error {
  constructor(message, status = "invalid") {
    super(message);
    this.status = status;
  }
}

const ascii = (bytes) => String.fromCharCode(...bytes);

function b64urlBytes(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

const b64urlJson = (text) => JSON.parse(new TextDecoder().decode(b64urlBytes(text)));

// 서명을 확인하기 전에 다루는 입력의 크기 상한. 작은 압축 데이터가 거대하게 풀리는 파일로 브라우저 메모리를
// 고갈시키지 못하게 한다. 우리 배지는 PNG 약 0.5MB, 배지 정보(JWT) 수 KB, 취소 목록은 131072비트(16KB) 단위다.
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOKEN_BYTES = 256 * 1024;
const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

async function inflate(bytes, format, limit) {
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format)).getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {  // 끝까지 풀지 않고 바로 멈춘다
      await reader.cancel();
      throw new BadgeError("압축을 푼 데이터가 너무 큽니다.");
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function extractToken(bytes) {
  if (bytes.length > MAX_FILE_BYTES) throw new BadgeError("파일이 너무 큽니다. 배지 PNG 파일인지 확인하세요.");
  if (!PNG_SIGNATURE.every((b, i) => bytes[i] === b)) {
    throw new BadgeError("PNG 파일이 아닙니다.");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = 8;
  while (pos + 8 <= bytes.length) {
    const length = view.getUint32(pos);
    const type = ascii(bytes.subarray(pos + 4, pos + 8));
    const data = bytes.subarray(pos + 8, pos + 8 + length);
    if (type === "iTXt") {
      // keyword \0 압축플래그 압축방식 언어태그 \0 번역키워드 \0 본문
      const k = data.indexOf(0);
      if (k > 0 && ascii(data.subarray(0, k)) === ITXT_KEYWORD) {
        const compressed = data[k + 1] === 1;
        const langEnd = data.indexOf(0, k + 3);
        const translatedEnd = data.indexOf(0, langEnd + 1);
        const text = data.subarray(translatedEnd + 1);
        if (!compressed && text.length > MAX_TOKEN_BYTES) throw new BadgeError("배지 정보가 너무 큽니다.");
        return new TextDecoder().decode(compressed ? await inflate(text, "deflate", MAX_TOKEN_BYTES) : text);
      }
    }
    if (type === "IEND") break;
    pos += 12 + length;
  }
  throw new BadgeError("배지 정보가 들어 있지 않은 PNG입니다.");
}

export function didToUrl(did) {
  if (!did.startsWith("did:web:")) throw new BadgeError(`지원하지 않는 발급기관 식별자입니다: ${did}`, "error");
  const [host, ...path] = did.slice("did:web:".length).split(":").map(decodeURIComponent);
  return path.length ? `https://${host}/${path.join("/")}/did.json` : `https://${host}/.well-known/did.json`;
}

function decodeJwt(token) {
  const parts = token.trim().split(".");
  if (parts.length !== 3) throw new BadgeError("배지 서명 형식이 올바르지 않습니다.");
  let header, payload;
  try {
    header = b64urlJson(parts[0]);
    payload = b64urlJson(parts[1]);
  } catch {
    throw new BadgeError("배지 데이터가 손상되었습니다.");
  }
  // JSON으로 읽혀도 객체가 아니면(null·숫자·배열 등) 배지가 아니다 — 뒤의 속성 접근에서 멈추지 않게 여기서 거른다
  if (!isObject(header) || !isObject(payload)) throw new BadgeError("배지 데이터가 손상되었습니다.");
  return { parts, header, payload };
}

const issuerId = (issuer) => (typeof issuer === "string" ? issuer : issuer?.id);

// JWT 헤더에 들어 있는 키는 누구나 넣을 수 있으므로 신뢰하지 않는다.
// 발급기관이 DID 문서로 공개한 키 중, 발급 권한(assertionMethod)이 있고 헤더가 가리키는 것만 쓴다(DID Core §5.3).
function pickKey(didDoc, did, header) {
  const resolveId = (id) => (id?.startsWith("#") ? did + id : id);
  const assertion = [].concat(didDoc.assertionMethod || []);
  const allowed = new Set(assertion.map((a) => resolveId(typeof a === "string" ? a : a?.id)));
  const methods = [...(didDoc.verificationMethod || []), ...assertion.filter((a) => typeof a === "object")]
    .filter((m) => allowed.has(resolveId(m?.id)) && m.publicKeyJwk?.kty === "RSA");
  let method;
  if (header.kid) method = methods.find((m) => m.id === header.kid || m.id === did + header.kid);
  else if (header.jwk) method = methods.find((m) => m.publicKeyJwk.n === header.jwk.n);
  else method = methods[0];
  if (!method) throw new BadgeError("발급기관이 발급용으로 공개한 키로 서명되지 않았습니다.");
  return method.publicKeyJwk;
}

const types = (value) => [].concat(value?.type || []);
const toSeconds = (iso) => Math.floor(Date.parse(iso) / 1000);
const REVOCATION_ENTRY = (e) => e?.type === "BitstringStatusListEntry" && (e.statusPurpose || "revocation") === "revocation";

// 서명이 맞아도 "배지"라는 보장은 없다(예: 같은 키로 서명된 취소 목록). OB 3.0 배지 구조와
// VC-JWT 필수 클레임(§8.2.6.1: iss·sub·nbf·jti가 배지 필드와 일치, exp 반영)을 확인한다.
const VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";
const OB_CONTEXT = /^https:\/\/purl\.imsglobal\.org\/spec\/ob\/v3p0\/context(-3\.\d\.\d)*\.json$/;

function checkCredential(p) {
  const bad = (why) => { throw new BadgeError(`Open Badges 배지 형식이 아닙니다: ${why}`); };
  // VC 2.0 문서의 첫 @context는 VC 기본 문맥, 둘째는 OB 3.0 문맥이어야 한다(스키마가 없어도 확인)
  const context = [].concat(p["@context"] ?? []);
  if (context[0] !== VC_CONTEXT || !OB_CONTEXT.test(context[1] ?? "")) bad("@context");
  const vcTypes = types(p);
  if (!vcTypes.includes("VerifiableCredential") ||
      !(vcTypes.includes("OpenBadgeCredential") || vcTypes.includes("AchievementCredential"))) bad("배지 유형");
  const subject = p.credentialSubject;
  if (!subject || typeof subject !== "object" || Array.isArray(subject)) bad("받은 사람 정보");
  if (!types(subject).includes("AchievementSubject")) bad("받은 사람 유형");
  if (!subject.id && [].concat(subject.identifier || []).length === 0) bad("받은 사람 식별자");
  const achievement = subject.achievement;
  if (!achievement || typeof achievement.id !== "string" || typeof achievement.name !== "string" ||
      !types(achievement).includes("Achievement")) bad("배지 정의");
  if (p.iss !== issuerId(p.issuer)) bad("iss가 발급기관과 다름");
  if (typeof p.sub !== "string" || p.sub !== subject.id) bad("sub가 받은 사람 식별자와 다름");
  if (typeof p.jti !== "string" || p.jti !== p.id) bad("jti가 배지 식별자와 다름");
  if (typeof p.nbf !== "number" || p.nbf !== toSeconds(p.validFrom)) bad("nbf가 발급 시각과 다름");
  if (p.exp !== undefined && (typeof p.exp !== "number" ||
      (p.validUntil !== undefined && p.exp !== toSeconds(p.validUntil)))) bad("exp가 유효 기간과 다름");
  for (const entry of [].concat(p.credentialStatus || []).filter(REVOCATION_ENTRY)) {
    if (!/^\d+$/.test(String(entry.statusListIndex ?? "")) || typeof entry.statusListCredential !== "string") {
      bad("취소 목록 항목");
    }
  }
}

// ── OB 3.0 §9.1: credentialSchema가 1EdTech JSON 스키마를 가리키면 그 스키마로 검사한다 ─────────────
// 공식 스키마 사본을 검증 페이지와 같은 곳에 두고 읽는다(외부 사이트를 매번 부르지 않게).
const SCHEMA_VALIDATOR = "1EdTechJsonSchemaValidator2019";
const SCHEMA_FILES = {
  "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json":
    "ob_v3p0_achievementcredential_schema.json",
};

// 공식 스키마(draft 2019-09)가 쓰는 키워드만 지원하는 작은 검사기. 모르는 키워드가 나오면 통과시키지 않고
// 실패한다 — 스키마가 바뀌었는데 검사를 조용히 건너뛰는 일이 없게. format(date-time·date)도 확인한다.
const SCHEMA_ANNOTATIONS = new Set(["$schema", "$id", "$comment", "$defs", "title", "description", "examples", "default"]);
const SCHEMA_KEYWORDS = new Set(["$ref", "type", "enum", "pattern", "format", "minItems", "items", "additionalItems",
  "contains", "required", "properties", "propertyNames", "additionalProperties", "allOf", "anyOf", "oneOf"]);
const patterns = new Map();

// RFC 3339 날짜·시각(JSON Schema의 date-time·date 형식). JavaScript Date.parse는 24:00이나 없는 날짜(2월 30일)도
// 받아들이므로 범위를 직접 확인한다. 윤초(초 60)는 UTC로 23:59:60일 때만 허용한다.
function isFullDate(y, m, d) {
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return m >= 1 && m <= 12 && d >= 1 && d <= days[m - 1];
}

export function isRfc3339Date(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  return !!m && isFullDate(+m[1], +m[2], +m[3]);
}

export function isRfc3339DateTime(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/.exec(s);
  if (!m) return false;
  const [hour, minute, second] = [+m[4], +m[5], +m[6]];
  const offset = m[8] ? (m[8] === "+" ? 1 : -1) * (+m[9] * 60 + +m[10]) : 0;
  if (!isFullDate(+m[1], +m[2], +m[3]) || hour > 23 || minute > 59 || second > 60) return false;
  if (m[8] && (+m[9] > 23 || +m[10] > 59)) return false;
  if (second === 60 && (((hour * 60 + minute - offset) % 1440) + 1440) % 1440 !== 23 * 60 + 59) return false;
  return true;
}

// 있으면 형식이 맞아야 하는 시각 값(밀리초). 없으면 undefined, 형식이 틀리면 null.
function isoTime(value) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !isRfc3339DateTime(value)) return null;
  const t = Date.parse(value.replace(/:60(?=[.Zz+-])/, ":59"));  // 윤초는 그 직전 초로 계산
  return Number.isNaN(t) ? null : t;
}

function epochTime(value) {
  if (value === undefined) return undefined;
  return typeof value === "number" && Number.isFinite(value) ? value * 1000 : null;
}

const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function isType(value, type) {
  switch (type) {
    case "object": return isObject(value);
    case "array": return Array.isArray(value);
    case "string": return typeof value === "string";
    case "boolean": return typeof value === "boolean";
    case "number": return typeof value === "number" && Number.isFinite(value);
    case "integer": return Number.isInteger(value);
    case "null": return value === null;
    default: throw new Error(`지원하지 않는 스키마 형식 ${type}`);
  }
}

function sameValue(a, b) {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((k) => own(b, k) && sameValue(a[k], b[k]));
}

function resolveRef(root, ref) {
  if (!ref.startsWith("#")) throw new Error(`외부 스키마 참조는 지원하지 않습니다: ${ref}`);
  return ref.slice(1).split("/").filter(Boolean).reduce((node, part) => {
    const key = decodeURIComponent(part).replace(/~1/g, "/").replace(/~0/g, "~");
    if (node === undefined || !own(node, key)) throw new Error(`스키마 참조를 찾을 수 없습니다: ${ref}`);
    return node[key];
  }, root);
}

function regex(pattern) {
  if (!patterns.has(pattern)) patterns.set(pattern, new RegExp(pattern));
  return patterns.get(pattern);
}

// value가 schema에 맞으면 null, 아니면 첫 문제를 설명하는 문자열
export function schemaError(root, schema, value, path = "$") {
  if (schema === true) return null;
  if (schema === false) return `${path}: 허용되지 않는 값`;
  for (const key of Object.keys(schema)) {
    if (!SCHEMA_KEYWORDS.has(key) && !SCHEMA_ANNOTATIONS.has(key)) throw new Error(`지원하지 않는 스키마 키워드 ${key}`);
  }
  const fail = (why) => `${path}: ${why}`;
  const sub = (s, v, p) => schemaError(root, s, v, p);
  let e;
  if (schema.$ref !== undefined && (e = sub(resolveRef(root, schema.$ref), value, path))) return e;
  if (schema.type !== undefined && ![].concat(schema.type).some((t) => isType(value, t))) {
    return fail(`${[].concat(schema.type).join("·")} 형식이어야 함`);
  }
  if (schema.enum !== undefined && !schema.enum.some((v) => sameValue(v, value))) return fail("허용되지 않는 값");
  if (typeof value === "string") {
    if (schema.pattern !== undefined && !regex(schema.pattern).test(value)) return fail("형식이 맞지 않음");
    if (schema.format === "date-time" && !isRfc3339DateTime(value)) return fail("날짜·시각 형식이 아님");
    if (schema.format === "date" && !isRfc3339Date(value)) return fail("날짜 형식이 아님");
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) return fail(`항목이 ${schema.minItems}개 이상이어야 함`);
    if (Array.isArray(schema.items)) {  // 앞쪽 항목마다 스키마가 따로 있고, 나머지는 additionalItems
      for (let i = 0; i < value.length; i++) {
        const s = i < schema.items.length ? schema.items[i] : schema.additionalItems;
        if (s !== undefined && (e = sub(s, value[i], `${path}[${i}]`))) return e;
      }
    } else if (schema.items !== undefined) {
      for (let i = 0; i < value.length; i++) if ((e = sub(schema.items, value[i], `${path}[${i}]`))) return e;
    }
    if (schema.contains !== undefined && !value.some((v, i) => !sub(schema.contains, v, `${path}[${i}]`))) {
      return fail("필요한 항목이 없음");
    }
  }
  if (isObject(value)) {
    for (const key of schema.required || []) if (!own(value, key)) return fail(`${key} 없음`);
    const props = schema.properties || {};
    for (const [key, v] of Object.entries(value)) {
      if (schema.propertyNames !== undefined && (e = sub(schema.propertyNames, key, `${path} 속성 이름 ${key}`))) return e;
      const s = own(props, key) ? props[key] : schema.additionalProperties;
      if (s !== undefined && (e = sub(s, v, `${path}.${key}`))) return e;
    }
  }
  for (const s of schema.allOf || []) if ((e = sub(s, value, path))) return e;
  if (schema.anyOf && !schema.anyOf.some((s) => !sub(s, value, path))) return fail("조건에 맞는 형식이 없음");
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((s) => !sub(s, value, path)).length;
    if (matches !== 1) return fail(matches ? "여러 형식에 동시에 해당함" : "맞는 형식이 없음");
  }
  return null;
}

async function checkSchema(payload, fetchFn, schemaBase) {
  for (const declared of [].concat(payload.credentialSchema || [])) {
    if (declared?.type !== SCHEMA_VALIDATOR) continue;  // 다른 방식의 스키마는 §9.1 검사 대상이 아니다
    const file = SCHEMA_FILES[declared.id];
    if (!file) throw new BadgeError(`Open Badges 배지 형식이 아닙니다: 지원하지 않는 스키마 ${declared.id}`);
    let schema;
    try {
      schema = JSON.parse(await fetchText(fetchFn, new URL(file, schemaBase).href));
    } catch (e) {
      throw new BadgeError(`배지 형식 검사에 필요한 스키마를 불러오지 못했습니다. (${e.message})`, "error");
    }
    let problem;
    try {
      problem = schemaError(schema, schema, payload);
    } catch (e) {  // 스키마를 이 검사기가 다루지 못함 — 배지 탓이 아니므로 '확인할 수 없음'
      throw new BadgeError(`배지 형식을 검사할 수 없습니다. (${e.message})`, "error");
    }
    if (problem) throw new BadgeError(`Open Badges 배지 형식이 아닙니다: 스키마 검사 실패 (${problem})`);
  }
}

async function verifyJwt(token, didDoc, did) {
  const { parts, header, payload } = decodeJwt(token);
  if (header.alg !== JWT_ALG) throw new BadgeError(`지원하지 않는 서명 방식입니다: ${header.alg}`);
  const jwk = pickKey(didDoc, did, header);
  const key = await crypto.subtle.importKey(
    "jwk", { kty: "RSA", n: jwk.n, e: jwk.e }, KEY_ALGORITHM, false, ["verify"]);
  const ok = await crypto.subtle.verify(
    KEY_ALGORITHM, key, b64urlBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!ok) throw new BadgeError("서명이 일치하지 않습니다. 배지 내용이 바뀌었거나 위조되었습니다.");
  return payload;
}

async function fetchText(fetchFn, url) {
  const res = await fetchFn(url, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${url} 응답 ${res.status}`);
  return res.text();
}

// 화면에서 링크로 쓰일 주소는 http(s)만 통과시킨다(javascript: 등은 버림).
function safeUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}

function describe(payload) {
  const subject = payload.credentialSubject || {};
  const achievement = subject.achievement || {};
  const nameId = [].concat(subject.identifier || []).find((i) => i.identityType === "name" && !i.hashed);
  const evidence = [].concat(payload.evidence || [])
    .map((e) => ({ url: safeUrl(e?.id), narrative: e?.narrative || e?.description || e?.name }))
    .filter((e) => e.url || e.narrative);
  return {
    evidence,
    badgeName: achievement.name,
    achievementId: achievement.id,
    criteria: achievement.criteria?.narrative,
    name: nameId?.identityHash,
    credentialNo: subject.licenseNumber,
    issuedAt: payload.validFrom,
    issuerName: typeof payload.issuer === "object" ? payload.issuer.name : undefined,
  };
}

const MIN_STATUS_LIST_BITS = 131072; // W3C Bitstring Status List 최소 크기(§2.1)

// 배지의 취소 항목을 모두 확인한다(하나라도 취소면 취소). 같은 목록은 한 번만 불러온다.
async function isRevoked(payload, didDoc, issuerDid, fetchFn, now) {
  const lists = new Map();
  for (const entry of [].concat(payload.credentialStatus || []).filter(REVOCATION_ENTRY)) {
    const url = entry.statusListCredential;
    if (!lists.has(url)) lists.set(url, await loadStatusList(url, didDoc, issuerDid, fetchFn, now));
    const bits = lists.get(url);
    const index = Number(entry.statusListIndex);  // checkCredential에서 숫자 문자열임을 확인함
    if (index >= bits.length * 8) throw new Error("취소 목록 인덱스 범위 오류");
    if (((bits[index >> 3] >> (7 - (index & 7))) & 1) === 1) return true;
  }
  return false;
}

async function loadStatusList(url, didDoc, issuerDid, fetchFn, now) {
  const list = await verifyJwt(await fetchText(fetchFn, url), didDoc, issuerDid);
  if (!types(list).includes("BitstringStatusListCredential")) throw new Error("취소 목록 형식이 아닙니다");
  if (issuerId(list.issuer) !== issuerDid) throw new Error("취소 목록의 발급기관이 다릅니다");
  // 같은 키로 서명된 다른 목록(다른 주소·다른 용도)을 대신 내미는 것을 막는다.
  if (list.id !== url) throw new Error("배지가 가리키는 취소 목록이 아닙니다");
  if (list.credentialSubject?.statusPurpose !== "revocation") throw new Error("취소(revocation) 목록이 아닙니다");
  // 목록 자체의 유효 기간: 아직 시작되지 않았거나 끝난 목록은 쓰지 않는다(validUntil을 요구하지는 않음)
  // 기간 값은 없어도 되지만, 있는데 형식이 틀리면 기한이 없는 것으로 보지 않고 목록을 쓰지 않는다.
  const times = { validFrom: isoTime(list.validFrom), nbf: epochTime(list.nbf),
                  validUntil: isoTime(list.validUntil), exp: epochTime(list.exp) };
  const broken = Object.keys(times).filter((k) => times[k] === null);
  if (broken.length) throw new Error(`취소 목록의 기간 값(${broken.join(", ")}) 형식이 올바르지 않습니다`);
  if ([times.validFrom, times.nbf].some((t) => t > now.getTime() + CLOCK_SKEW_MS)) {
    throw new Error("취소 목록의 유효 기간이 아직 시작되지 않았습니다");
  }
  if ([times.validUntil, times.exp].some((t) => t < now.getTime() - CLOCK_SKEW_MS)) {
    throw new Error("취소 목록의 유효 기간이 지났습니다");
  }
  const encoded = list.credentialSubject?.encodedList || "";
  if (!encoded.startsWith("u")) throw new Error("취소 목록 형식 오류");
  const bits = await inflate(b64urlBytes(encoded.slice(1)), "gzip", MAX_STATUS_LIST_BYTES);
  if (bits.length * 8 < MIN_STATUS_LIST_BITS) throw new Error("취소 목록이 표준 최소 크기보다 작습니다");
  return bits;
}

// 발급 직후 시계가 조금 느린 PC에서 "아직 유효하지 않음"이 뜨지 않도록 허용하는 오차
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function checkValidity(payload, now) {
  // §8.2.6.1: exp가 있으면 그것이 유효 기간 끝이다. 기간 값이 있는데 형식이 틀리면 기한이 없는 것으로 보지 않는다.
  const from = isoTime(payload.validFrom);
  const until = payload.exp !== undefined ? epochTime(payload.exp) : isoTime(payload.validUntil);
  if (from === null || until === null) throw new BadgeError("Open Badges 배지 형식이 아닙니다: 유효 기간 값");
  if (from > now.getTime() + CLOCK_SKEW_MS) throw new BadgeError("아직 유효 기간이 시작되지 않은 배지입니다.");
  if (until < now.getTime() - CLOCK_SKEW_MS) throw new BadgeError("유효 기간이 지난 배지입니다.");
}

/**
 * 결과 status: valid(유효) | revoked(취소) | invalid(위·변조/손상) | foreign(다른 발급기관)
 *              | unknown(서명 유효, 취소 여부 확인 불가) | error(발급기관 정보를 못 불러와 확인 불가)
 * schemaBase: 공식 스키마 사본(ob_v3p0_achievementcredential_schema.json)이 있는 주소. 기본은 이 파일과 같은 곳.
 */
export async function verifyBadge(bytes, { issuerDid, fetchFn = (url, init) => fetch(url, init), now = new Date(),
                                           schemaBase = new URL("./", import.meta.url).href }) {
  let token, payload;
  try {
    token = await extractToken(bytes);
    payload = decodeJwt(token).payload;
  } catch (e) {
    return { status: "invalid", reason: e.message };
  }
  if (issuerId(payload.issuer) !== issuerDid) {
    return { status: "foreign", reason: "발급기관이 다릅니다." };
  }

  let didDoc;
  try {
    didDoc = JSON.parse(await fetchText(fetchFn, didToUrl(issuerDid)));
    if (didDoc.id !== issuerDid) throw new Error("DID 문서 식별자가 다릅니다");
  } catch (e) {
    return { status: "error", reason: `발급기관 공개키를 불러오지 못했습니다. (${e.message})` };
  }

  try {
    payload = await verifyJwt(token, didDoc, issuerDid);
    checkCredential(payload);
    await checkSchema(payload, fetchFn, schemaBase);
    checkValidity(payload, now);
  } catch (e) {
    return { status: e.status || "invalid", reason: e.message };
  }
  const info = describe(payload);

  try {
    const revoked = await isRevoked(payload, didDoc, issuerDid, fetchFn, now);
    return { status: revoked ? "revoked" : "valid", info, payload };
  } catch (e) {
    return { status: "unknown", reason: e.message, info, payload };
  }
}

const toHex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");

// 발급 시와 같은 규칙(공백 제거·소문자)으로 정규화해 sha256(email + salt)를 대조한다.
export async function checkOwner(payload, email) {
  const target = [].concat(payload?.credentialSubject?.identifier || []).find((i) => i.identityType === "emailAddress");
  if (!target) return false;
  const normalized = email.trim().toLowerCase();
  if (!target.hashed) return target.identityHash.trim().toLowerCase() === normalized;
  const [algorithm, hex] = target.identityHash.split("$");
  if (algorithm !== "sha256" || !hex) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized + (target.salt || "")));
  return toHex(digest) === hex.toLowerCase();
}
