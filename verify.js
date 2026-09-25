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

async function inflate(bytes, format) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function extractToken(bytes) {
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
        return new TextDecoder().decode(compressed ? await inflate(text, "deflate") : text);
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
  try {
    return { parts, header: b64urlJson(parts[0]), payload: b64urlJson(parts[1]) };
  } catch {
    throw new BadgeError("배지 데이터가 손상되었습니다.");
  }
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
function checkCredential(p) {
  const bad = (why) => { throw new BadgeError(`Open Badges 배지 형식이 아닙니다: ${why}`); };
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

async function isRevoked(payload, didDoc, issuerDid, fetchFn) {
  const entry = [].concat(payload.credentialStatus || []).find(REVOCATION_ENTRY);
  if (!entry) return false;
  const list = await verifyJwt(await fetchText(fetchFn, entry.statusListCredential), didDoc, issuerDid);
  if (!types(list).includes("BitstringStatusListCredential")) throw new Error("취소 목록 형식이 아닙니다");
  if (issuerId(list.issuer) !== issuerDid) throw new Error("취소 목록의 발급기관이 다릅니다");
  // 같은 키로 서명된 다른 목록(다른 주소·다른 용도)을 대신 내미는 것을 막는다.
  if (list.id !== entry.statusListCredential) throw new Error("배지가 가리키는 취소 목록이 아닙니다");
  if (list.credentialSubject?.statusPurpose !== "revocation") throw new Error("취소(revocation) 목록이 아닙니다");
  const encoded = list.credentialSubject?.encodedList || "";
  if (!encoded.startsWith("u")) throw new Error("취소 목록 형식 오류");
  const bits = await inflate(b64urlBytes(encoded.slice(1)), "gzip");
  if (bits.length * 8 < MIN_STATUS_LIST_BITS) throw new Error("취소 목록이 표준 최소 크기보다 작습니다");
  const index = Number(entry.statusListIndex);  // checkCredential에서 숫자 문자열임을 확인함
  if (index >= bits.length * 8) throw new Error("취소 목록 인덱스 범위 오류");
  return ((bits[index >> 3] >> (7 - (index & 7))) & 1) === 1;
}

// 발급 직후 시계가 조금 느린 PC에서 "아직 유효하지 않음"이 뜨지 않도록 허용하는 오차
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function checkValidity(payload, now) {
  const from = Date.parse(payload.validFrom);
  if (!Number.isNaN(from) && from > now.getTime() + CLOCK_SKEW_MS) {
    throw new BadgeError("아직 유효 기간이 시작되지 않은 배지입니다.");
  }
  // §8.2.6.1: exp가 있으면 그것이 유효 기간 끝이다.
  const until = typeof payload.exp === "number" ? payload.exp * 1000 : Date.parse(payload.validUntil);
  if (!Number.isNaN(until) && until < now.getTime() - CLOCK_SKEW_MS) throw new BadgeError("유효 기간이 지난 배지입니다.");
}

/**
 * 결과 status: valid(유효) | revoked(취소) | invalid(위·변조/손상) | foreign(다른 발급기관)
 *              | unknown(서명 유효, 취소 여부 확인 불가) | error(발급기관 정보를 못 불러와 확인 불가)
 */
export async function verifyBadge(bytes, { issuerDid, fetchFn = (url, init) => fetch(url, init), now = new Date() }) {
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
    checkValidity(payload, now);
  } catch (e) {
    return { status: e.status || "invalid", reason: e.message };
  }
  const info = describe(payload);

  try {
    const revoked = await isRevoked(payload, didDoc, issuerDid, fetchFn);
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
