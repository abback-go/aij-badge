// AI Jungle Badge 검증 로직 (Open Badges 3.0, VC-JWT/EdDSA).
// DOM을 쓰지 않아 브라우저와 Node(테스트) 양쪽에서 돌아간다. 외부 라이브러리 없이
// WebCrypto Ed25519(Chrome 137+, Firefox 129+, Safari 17+)와 DecompressionStream만 쓴다.

const ITXT_KEYWORD = "openbadgecredential";
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
// 발급기관이 DID 문서로 공개한 키 중 헤더가 가리키는 것만 쓴다.
function pickKey(didDoc, did, header) {
  const methods = (didDoc.verificationMethod || []).filter((m) => m.publicKeyJwk?.crv === "Ed25519");
  let method;
  if (header.kid) method = methods.find((m) => m.id === header.kid || m.id === did + header.kid);
  else if (header.jwk) method = methods.find((m) => m.publicKeyJwk.x === header.jwk.x);
  else method = methods[0];
  if (!method) throw new BadgeError("발급기관이 공개한 키로 서명되지 않았습니다.");
  return method.publicKeyJwk;
}

async function verifyJwt(token, didDoc, did) {
  const { parts, header, payload } = decodeJwt(token);
  if (header.alg !== "EdDSA") throw new BadgeError(`지원하지 않는 서명 방식입니다: ${header.alg}`);
  const jwk = pickKey(didDoc, did, header);
  const key = await crypto.subtle.importKey(
    "jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" }, key, b64urlBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!ok) throw new BadgeError("서명이 일치하지 않습니다. 배지 내용이 바뀌었거나 위조되었습니다.");
  return payload;
}

async function fetchText(fetchFn, url) {
  const res = await fetchFn(url, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${url} 응답 ${res.status}`);
  return res.text();
}

function describe(payload) {
  const subject = payload.credentialSubject || {};
  const achievement = subject.achievement || {};
  const nameId = [].concat(subject.identifier || []).find((i) => i.identityType === "name" && !i.hashed);
  return {
    badgeName: achievement.name,
    achievementId: achievement.id,
    criteria: achievement.criteria?.narrative,
    name: nameId?.identityHash,
    credentialNo: subject.licenseNumber,
    issuedAt: payload.validFrom,
    issuerName: typeof payload.issuer === "object" ? payload.issuer.name : undefined,
  };
}

async function isRevoked(payload, didDoc, issuerDid, fetchFn) {
  const entry = [].concat(payload.credentialStatus || []).find(
    (e) => e.type === "BitstringStatusListEntry" && (e.statusPurpose || "revocation") === "revocation");
  if (!entry) return false;
  const list = await verifyJwt(await fetchText(fetchFn, entry.statusListCredential), didDoc, issuerDid);
  if (issuerId(list.issuer) !== issuerDid) throw new Error("취소 목록의 발급기관이 다릅니다");
  const encoded = list.credentialSubject?.encodedList || "";
  if (!encoded.startsWith("u")) throw new Error("취소 목록 형식 오류");
  const bits = await inflate(b64urlBytes(encoded.slice(1)), "gzip");
  const index = Number.parseInt(entry.statusListIndex, 10);
  if (!(index >= 0 && index < bits.length * 8)) throw new Error("취소 목록 인덱스 범위 오류");
  return ((bits[index >> 3] >> (7 - (index & 7))) & 1) === 1;
}

function checkValidity(payload, now) {
  const from = Date.parse(payload.validFrom);
  if (!Number.isNaN(from) && from > now.getTime()) throw new BadgeError("아직 유효 기간이 시작되지 않은 배지입니다.");
  const until = Date.parse(payload.validUntil);
  if (!Number.isNaN(until) && until < now.getTime()) throw new BadgeError("유효 기간이 지난 배지입니다.");
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
