"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const hkdf_1 = require("@noble/hashes/hkdf");
const kyber_1 = require("./kyber");
const hashing_1 = require("./hashing");
const dilithium_1 = require("./dilithium");
class HarmonyCrypto {
    static hash(data, algo) {
        return hashing_1.hashing_functions[algo](new TextEncoder().encode(data));
    }
    static hash_hex(data, algo) {
        const bytes = this.hash(data, algo);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    static async hkdf_derive(seed, salt, info, length) {
        return (0, hkdf_1.hkdf)(hashing_1.hashing_functions.sha3_256, seed, salt, new TextEncoder().encode(info), length);
    }
    async get_kyber_kypair(algo, seed, info) {
        const infoStr = info ? ` ${info}` : '';
        const derivedSeed = (0, hkdf_1.hkdf)(hashing_1.hashing_functions.sha3_512, seed, new Uint8Array(0), new TextEncoder().encode(`${algo}${infoStr}`), 64);
        return await new kyber_1.Kyber().get_keypair(algo, derivedSeed);
    }
    async get_kyber_keypair_hex(algo, seed) {
        const { public_key, secret_key } = await this.get_kyber_kypair(algo, seed);
        const toHex = (buf) => [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
        return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
    }
    async kyber_encapsulate(algo, public_key) {
        return await new kyber_1.Kyber().encapsulate(algo, public_key);
    }
    async kyber_decapsulate(algo, msg, secret_key) {
        return await new kyber_1.Kyber().decapsulate(algo, msg, secret_key);
    }
    async get_dilithium_keypair(algo, seed, info) {
        const infoStr = info ? ` ${info}` : '';
        const derivedSeed = (0, hkdf_1.hkdf)(hashing_1.hashing_functions.sha3_512, seed, new Uint8Array(0), new TextEncoder().encode(`${algo}${infoStr}`), 32);
        return await dilithium_1.Dilithium.get_keypair(derivedSeed, algo);
    }
    async get_dilithium_keypair_hex(seed, algo) {
        const { public_key, secret_key } = await this.get_dilithium_keypair(algo, seed);
        const toHex = (buf) => [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
        return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
    }
    async dilithium_sign(msg, secret_key, algo) {
        return await dilithium_1.Dilithium.sign(msg, secret_key, algo);
    }
    async dilithium_verify(signature, msg, public_key, algo) {
        return await dilithium_1.Dilithium.verify(signature, msg, public_key, algo);
    }
}
exports.default = HarmonyCrypto;
async function main() {
    const hrc = new HarmonyCrypto();
    let msg = "Hi";
    const seed = new Uint8Array(64);
    seed.fill(0);
    const signing_keypair = await hrc.get_dilithium_keypair("dilithium_2", seed, "signing keypair");
    const encapsulating_keypair = await hrc.get_kyber_kypair("kyber512", seed, "encapsulating keypair");
    const signature = await hrc.dilithium_sign(new TextEncoder().encode(msg), signing_keypair.secret_key, "dilithium_2");
    msg = "Not hi"; // Intentional
    const verified = await hrc.dilithium_verify(signature, new TextEncoder().encode(msg), signing_keypair.public_key, "dilithium_2");
    const { cyphertext, shared_secret } = await hrc.kyber_encapsulate("kyber512", encapsulating_keypair.public_key);
    const decapsulated = await hrc.kyber_decapsulate("kyber512", cyphertext, encapsulating_keypair.secret_key);
    console.log(verified); // should be false
    console.log(shared_secret.length // should be true
        === decapsulated.length && shared_secret.every((v, i) => v === decapsulated[i]));
}
main();
//# sourceMappingURL=index.js.map