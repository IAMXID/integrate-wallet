"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveDID = exports.verifyNFTcredentialArray = exports.newNFTcredential = exports.generateProofJWS = exports.stringToArray = exports.arrayToString = exports.verifyIamxNftSignatureArray = exports.getPubKey = exports.createDID_ES512_fromKeys = exports.createDID_ES512 = exports.createDID = exports.timestamp = exports.createSignedMessage = exports.decodeCBOR = exports.encodeCBOR = exports.verifySignature = exports.messageSignature = exports.base58ToBase64 = exports.base64ToBase58 = exports.base58ToString = exports.stringToBase58 = exports.messageSignaturePassPhrase = exports.createRSAKeypair = exports.ledgers = void 0;
// import cbor from "cbor"
const crypto_1 = require("crypto");
const jose = __importStar(require("jose"));
const bs58_1 = __importDefault(require("bs58"));
const cbor_1 = __importDefault(require("cbor"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const uuid_1 = require("uuid");
var ledgers;
(function (ledgers) {
    ledgers["eth"] = "eth";
    ledgers["cardano"] = "cardano";
    ledgers["btc"] = "btc";
    ledgers["ipfs"] = "ipfs";
    ledgers["plain"] = "plain";
    ledgers["web"] = "web";
})(ledgers = exports.ledgers || (exports.ledgers = {}));
// methods
/**
 *
 * @param passphrase
 * @returns
 */
const createRSAKeypair = (passphrase) => {
    return (0, crypto_1.generateKeyPairSync)("rsa", {
        modulusLength: 4096,
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
            cipher: "aes-256-cbc",
            passphrase: passphrase,
        },
    });
};
exports.createRSAKeypair = createRSAKeypair;
/**
 *
 * @param message the message to be signed in cbor
 * @param privateKey privateKey of type RSA
 * @param passphrase passphrase for privateKey
 * @returns
 */
const messageSignaturePassPhrase = (message, privateKey, passphrase) => {
    const signer = (0, crypto_1.createSign)("rsa-sha256");
    const signature = signer.update(message).sign({
        key: privateKey,
        passphrase: passphrase,
    }, "base64");
    const signatureBase58 = (0, exports.base64ToBase58)(signature); // convert the signature to base 64
    console.log(signature.length);
    console.log(signatureBase58.length);
    return signatureBase58;
};
exports.messageSignaturePassPhrase = messageSignaturePassPhrase;
const stringToBase58 = (input) => {
    let buff = Buffer.from(input);
    let base58string = bs58_1.default.encode(buff);
    return base58string;
};
exports.stringToBase58 = stringToBase58;
const base58ToString = (input) => {
    let bs59Bytes = bs58_1.default.decode(input);
    let base58String = Buffer.from(bs59Bytes).toString("ascii");
    return base58String;
};
exports.base58ToString = base58ToString;
const base64ToBase58 = (signatureBase64) => {
    const buf = Buffer.from(signatureBase64);
    const base58 = bs58_1.default.encode(buf);
    return base58;
};
exports.base64ToBase58 = base64ToBase58;
const base58ToBase64 = (signatureBase64) => {
    const bytes = bs58_1.default.decode(signatureBase64);
    const _string = Buffer.from(bytes).toString("ascii");
    return _string;
};
exports.base58ToBase64 = base58ToBase64;
/**
 *
 * @param message
 * @param privateKey
 * @param passphrase
 * @returns
 */
const messageSignature = (message, privateKey) => {
    const signer = (0, crypto_1.createSign)("rsa-sha256");
    // const signer = createSign("RSA-SHA3-512")
    const signature = signer.update(message).sign({
        key: privateKey,
    }, "base64");
    const signatureBase58 = (0, exports.base64ToBase58)(signature); // convert the signature to base 64
    return signatureBase58;
};
exports.messageSignature = messageSignature;
/**
 *
 * @param message
 * @param signedMessage
 * @param publicKey
 * @returns
 */
const verifySignature = (message, signedMessage, publicKey) => {
    const verifier = (0, crypto_1.createVerify)("rsa-sha256");
    verifier.update(message);
    return verifier.verify(publicKey, signedMessage, "base64");
};
exports.verifySignature = verifySignature;
const encodeCBOR = (jsonPayload) => {
    return cbor_1.default.encode(jsonPayload);
};
exports.encodeCBOR = encodeCBOR;
const decodeCBOR = (cborString) => {
    return cbor_1.default.decodeAllSync(cborString);
};
exports.decodeCBOR = decodeCBOR;
/**
 *
 * @param messageJSON
 * @param privateKey
 * @param passphrase
 * @returns
 */
const createSignedMessage = (messageJSON, privateKey, passphrase) => {
    // let cborMessage = cbor.encode(messageJSON).createHash("sha256")
    return (0, exports.messageSignaturePassPhrase)(JSON.stringify(messageJSON), privateKey, passphrase);
};
exports.createSignedMessage = createSignedMessage;
const timestamp = () => {
    return new Date().toISOString();
};
exports.timestamp = timestamp;
/**
 *
 * @param ledgers
 * @param versioninfo in SemVer
 * @param description desctiption
 * @returns
 */
const createDID = (ledger, versioninfo, description) => {
    // TODO add seed or  Key Derivation Functions
    const keypairs = (0, crypto_1.generateKeyPairSync)("rsa", {
        modulusLength: 4096,
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
        },
    });
    // clean publicKey
    const pubkeyTrimmed = keypairs.publicKey
        .replace(/(\r\n|\n|\r)/gm, "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");
    // console.log(pubkeyTrimmed)
    let buff = Buffer.from(pubkeyTrimmed);
    let pubKey_base58btc = bs58_1.default.encode(buff);
    const didID = `did:iamx:${ledger}:zgg${pubKey_base58btc}`;
    const timestamp = new Date().toISOString();
    const didDocument = {
        context: [
            "https://www.w3.org/ns/did/v1",
            (0, exports.stringToArray)("https://github.com/IAMXID/did-method-iamx/blob/main/IAMX_DID_method.md"),
        ],
        id: (0, exports.stringToArray)(didID),
        updated: (0, exports.stringToArray)(timestamp),
        version: versioninfo,
        description: (0, exports.stringToArray)(description),
        verificationMethod: [
            {
                id: (0, exports.stringToArray)(`${didID}#key-1`),
                type: "RSA_mod4096",
                controller: (0, exports.stringToArray)(didID),
                publicKey: (0, exports.stringToArray)(pubkeyTrimmed),
            },
        ],
        authentication: [
            didID,
            {
                id: (0, exports.stringToArray)(`${didID}#key-1`),
                type: "RSA_mod4096",
                controller: (0, exports.stringToArray)(didID),
                publicKey: (0, exports.stringToArray)(pubkeyTrimmed),
            },
        ],
    };
    return {
        didDocument: didDocument,
        privateKey: keypairs.privateKey,
        publicKey: keypairs.publicKey,
    };
};
exports.createDID = createDID;
const addSPKIPrefixSufix = (key) => {
    return `-----BEGIN PUBLIC KEY-----\n${key}\n-----END PUBLIC KEY-----\r\n`;
};
/**
 *
 * @param ledger
 * @param versioninfo in SemVer
 * @param description desctiption
 * @returns
 */
const createDID_ES512 = (ledger) => __awaiter(void 0, void 0, void 0, function* () {
    // ECDSA using P-521 and SHA-512 -> https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    const keys = yield jose.generateKeyPair("ES512", { extractable: true });
    const privateKeyString = yield jose.exportPKCS8(keys.privateKey);
    const publicKeyString = yield jose.exportSPKI(keys.publicKey);
    const privateJwk = yield jose.exportJWK(keys.privateKey);
    const publicJwk = yield jose.exportJWK(keys.publicKey);
    // clean publicKey
    const pubkeyTrimmed = publicKeyString
        .replace(/(\r\n|\n|\r)/gm, "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");
    let pubKey_base58btc = (0, exports.stringToBase58)(pubkeyTrimmed);
    const didID = `did:iamx:${ledger}:z2J9${pubKey_base58btc}`;
    let didDocument;
    if (ledger === ledgers.cardano) {
        didDocument = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                (0, exports.stringToArray)("https://w3id.org/security/suites/jws-2020/v1"),
            ],
            id: (0, exports.stringToArray)(didID),
            // version: versioninfo,
            verificationMethod: [
                {
                    id: (0, exports.stringToArray)(`${didID}#key-1`),
                    type: "JsonWebKey2020",
                    controller: (0, exports.stringToArray)(didID),
                    publicKeyJwk: publicJwk,
                },
            ],
            authentication: [(0, exports.stringToArray)(didID)],
        };
    }
    else {
        didDocument = {
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            id: didID,
            // version: versioninfo,
            verificationMethod: [
                {
                    id: `${didID}#key-1`,
                    type: "JsonWebKey2020",
                    controller: didID,
                    publicKeyJwk: publicJwk,
                },
            ],
            authentication: [didID],
        };
    }
    return {
        didDocument: didDocument,
        didID: didID,
        pkcs8: privateKeyString,
        spki: publicKeyString,
        keys: keys,
    };
});
exports.createDID_ES512 = createDID_ES512;
/**
 *
 * @param ledger
 * @param versioninfo in SemVer
 * @param description desctiption
 * @returns
 */
const createDID_ES512_fromKeys = (publicKey, privateKey, ledger) => __awaiter(void 0, void 0, void 0, function* () {
    // ECDSA using P-521 and SHA-512 -> https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    console.log("publicKey", publicKey);
    console.log("privateKey", privateKey);
    console.log("ledger", ledger);
    const _publicKey = yield jose.importSPKI(publicKey, "ES512");
    const _privateKey = yield jose.importPKCS8(privateKey, "ES512");
    const privateKeyString = yield jose.exportPKCS8(_privateKey);
    const publicKeyString = yield jose.exportSPKI(_publicKey);
    const publicJwk = yield jose.exportJWK(_publicKey);
    const privateJwk = yield jose.exportJWK(_privateKey);
    const fingerprint = `${(0, uuid_1.v4)()}`;
    const uuid = `${(0, uuid_1.v4)()}`;
    // clean publicKey
    const pubkeyTrimmed = publicKey
        .replace(/(\r\n|\n|\r)/gm, "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");
    let pubKey_base58btc = (0, exports.stringToBase58)(pubkeyTrimmed);
    const didID = `did:iamx:${ledger}:z2J9${uuid}.${fingerprint}`;
    const didDocument = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            (0, exports.stringToArray)("https://w3id.org/security/suites/jws-2020/v1"),
        ],
        id: (0, exports.stringToArray)(didID),
        // version: versioninfo,
        verificationMethod: [
            {
                id: (0, exports.stringToArray)(`${didID}#key-1`),
                type: "JsonWebKey2020",
                controller: (0, exports.stringToArray)(didID),
                publicKeyJwk: publicJwk,
            },
        ],
        authentication: [(0, exports.stringToArray)(didID)],
    };
    return {
        didDocument: didDocument,
        didID: didID,
        pkcs8: privateKeyString,
        spki: publicKeyString,
    };
});
exports.createDID_ES512_fromKeys = createDID_ES512_fromKeys;
const getPubKey = (didID) => {
    // Placholder to retrieve PublicKey from DID
    let didPKey_part = didID.replace("did:iamx:cardanozgg", "");
    // console.log("didPKey: ", didPKey_part)
    let didPKey_array = bs58_1.default.decode(didPKey_part);
    // console.log(didPKey_array)
    let didPKey = String.fromCharCode.apply(null, didPKey_array);
    didPKey = `-----BEGIN PUBLIC KEY-----\n${didPKey}\n-----END PUBLIC KEY-----\n`;
    // let didPKey_dc = bs58.decode(didPKey.replace("did:iamx:cardanozgg", ""))
    // console.log(didPKey_dc)
    // console.log(didPKey)
    return didPKey;
};
exports.getPubKey = getPubKey;
const getPubKey2 = (didID) => {
    // Placholder to retrieve PublicKey from DID
    let didPKey_part = didID.replace("did:iamx:ipfs:zgg", "");
    // console.log("didPKey: ", didPKey_part)
    let didPKey_array = bs58_1.default.decode(didPKey_part);
    // console.log(didPKey_array)
    let didPKey = String.fromCharCode.apply(null, didPKey_array);
    didPKey = `-----BEGIN PUBLIC KEY-----\n${didPKey}\n-----END PUBLIC KEY-----\n`;
    // let didPKey_dc = bs58.decode(didPKey.replace("did:iamx:cardanozgg", ""))
    // console.log(didPKey_dc)
    // console.log(didPKey)
    return didPKey;
};
exports.getPubKey2 = getPubKey2;
/**
 *
 * @param message
 * @param signatures
 * @returns
 */
const verifyIamxNftSignatureArray = (message, signatures) => {
    console.log("verifyIAMXSignatureArray");
    let checkResults = [];
    // getDids
    for (let i = 0; i < signatures.length; i++) {
        let sig = signatures[i];
        const DIDstring = (0, exports.arrayToString)(sig.DID);
        const pKey = (0, exports.getPubKey)(DIDstring[0]);
        // verify
        const verifier = (0, crypto_1.createVerify)("rsa-sha256");
        if (i === 0) {
            verifier.update(message); // first signature is agains payload
        }
        else {
            let signatureStringPreviousSig = (0, exports.arrayToString)(signatures[i - 1].signature)[0];
            verifier.update(signatureStringPreviousSig); // follow up signatures are againt previous sigmnature
        }
        let signatureString = (0, exports.arrayToString)(sig.signature)[0];
        let base64Sig = (0, exports.base58ToBase64)(signatureString);
        let check = verifier.verify(pKey, base64Sig, "base64");
        checkResults.push(check);
    }
    const allChecks = checkResults.every((val) => val === true);
    return {
        allSignaturesOK: allChecks,
        checks: checkResults,
    };
};
exports.verifyIamxNftSignatureArray = verifyIamxNftSignatureArray;
/**
 *
 * @param message
 * @param signatures
 * @returns
 */
const verifyIamxNftSignatureArray2 = (message, signatures) => {
    console.log("verifyIAMXSignatureArray");
    let checkResults = [];
    // getDids
    for (let i = 0; i < signatures.length; i++) {
        let sig = signatures[i];
        const DIDstring = (0, exports.arrayToString)(sig.DID);
        const pKey = (0, exports.getPubKey2)(DIDstring[0]);
        // verify
        const verifier = (0, crypto_1.createVerify)("rsa-sha256");
        if (i === 0) {
            verifier.update(message); // first signature is agains payload
        }
        else {
            let signatureStringPreviousSig = (0, exports.arrayToString)(signatures[i - 1].signature)[0];
            verifier.update(signatureStringPreviousSig); // follow up signatures are againt previous sigmnature
        }
        let signatureString = (0, exports.arrayToString)(sig.signature)[0];
        let base64Sig = (0, exports.base58ToBase64)(signatureString);
        let check = verifier.verify(pKey, base64Sig, "base64");
        checkResults.push(check);
    }
    const allChecks = checkResults.every((val) => val === true);
    return {
        allSignaturesOK: allChecks,
        checks: checkResults,
    };
};
exports.verifyIamxNftSignatureArray2 = verifyIamxNftSignatureArray2;
/**
 *
 * @param input string array to be merged. 1 level of string nesting is supported
 * @returns will return an array allway
 */
const arrayToString = (input) => {
    let stringARR = [];
    if (typeof input === "string") {
        // console.log("arrayToString STRING: ", input)
        return [input];
    }
    else {
        for (let i = 0; i < input.length; i++) {
            if (typeof input[i] === "string") {
                // console.log("arrayToString STRING[]: ", input[i])
                stringARR.push(input[i].toString());
            }
            else if (typeof input[i] === "object") {
                // console.log("arrayToString STRING[[]]: ", input[i])
                let mergedString = "";
                for (let j = 0; j < input[i].length; j++) {
                    mergedString += input[i][j];
                }
                stringARR.push(mergedString);
            }
        }
        return stringARR;
    }
};
exports.arrayToString = arrayToString;
/**
 *
 * @param input
 * @param maxlenght
 * @returns
 */
const stringToArray = (input, maxlenght) => {
    if (!maxlenght) {
        maxlenght = 64;
    }
    if (input.length > maxlenght) {
        // split array in chunks of max lenght
        const chunks = ~~(input.length / maxlenght);
        const lastChunk = input.length % maxlenght;
        // console.log(chunks, lastChunk)
        let stringArr = [];
        for (let i = 0; i < chunks; i++) {
            // console.log("--->", input.slice(i * maxlenght, i * maxlenght + maxlenght))
            stringArr.push(input.slice(i * maxlenght, i * maxlenght + maxlenght));
        }
        if (lastChunk > 0) {
            stringArr.push(input.slice(chunks * maxlenght, chunks * maxlenght + lastChunk));
        }
        return [stringArr];
    }
    else {
        return input;
    }
};
exports.stringToArray = stringToArray;
/**
 *
 * @param input
 * @returns
 */
const generateProofJWS = (input) => __awaiter(void 0, void 0, void 0, function* () {
    const privateKey = yield jose.importPKCS8(input.pkcs8, "ES512");
    const jws = yield new jose.CompactSign(new TextEncoder().encode(JSON.stringify(input.payload)))
        .setProtectedHeader({
        alg: "ES512",
        crv: "P-521",
        typ: "JWS",
    })
        .sign(privateKey);
    // console.log(jws)
    if (input.ledger === ledgers.cardano) {
        return {
            type: "JsonWebSignature2020",
            created: (0, exports.timestamp)(),
            verificationMethod: (0, exports.stringToArray)(input.verificationMethod),
            proofPurpose: "assertionMethod",
            proofValue: (0, exports.stringToArray)(jws),
        };
    }
    else {
        return {
            type: "JsonWebSignature2020",
            created: (0, exports.timestamp)(),
            verificationMethod: input.verificationMethod,
            proofPurpose: "assertionMethod",
            proofValue: jws,
        };
    }
});
exports.generateProofJWS = generateProofJWS;
const newNFTcredential = (input) => {
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        type: ["VerifiableCredential"],
        issuer: input.issuer,
        issuanceDate: (0, exports.timestamp)(),
        credentialSubject: [input.credentialSubject],
        proof: [input.proof],
    };
};
exports.newNFTcredential = newNFTcredential;
const verifyNFTcredentialArray = (credential) => __awaiter(void 0, void 0, void 0, function* () {
    let verifications = [];
    let payloadString;
    let protectedHeaderString;
    for (let i = 0; i < credential.proof.length; i++) {
        const proof = (0, exports.arrayToString)(credential.proof[i].proofValue)[0];
        const didID = (0, exports.arrayToString)(credential.proof[i].verificationMethod)[0];
        const didDoc = yield (0, exports.resolveDID)(didID);
        const publicKey = yield jose.importJWK(didDoc.verificationMethod[0].publicKeyJwk, didDoc.verificationMethod[0].publicKeyJwk.crv);
        const { payload, protectedHeader } = yield jose.compactVerify(proof, publicKey);
        payloadString = new TextDecoder().decode(payload);
        protectedHeaderString = protectedHeader;
        const test = payloadString === JSON.stringify(credential.credentialSubject[i]);
        // console.log(test)
        verifications.push(test);
    }
    const allVerified = verifications.every((val) => val === true);
    return {
        verified: allVerified,
        checks: verifications,
        payloadString: "payloadString",
        protectedHeader: protectedHeaderString,
    };
});
exports.verifyNFTcredentialArray = verifyNFTcredentialArray;
const resolveDID = (didID) => {
    // Just pseudo Code here for testing
    const name = didID.slice(-5);
    const didDoc = fs_1.default.readFileSync(path_1.default.join(__dirname, "../keys", `${name}.json`), "utf-8");
    // console.log("resolveDIDdoc: ", JSON.parse(didDoc))
    return JSON.parse(didDoc);
};
exports.resolveDID = resolveDID;
//# sourceMappingURL=iamx_methods.js.map
