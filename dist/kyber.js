"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Kyber = void 0;
const mlkem_1 = require("mlkem");
const kyber_algorithms = {
    kyber512: mlkem_1.MlKem512,
    kyber768: mlkem_1.MlKem768,
    kyber1024: mlkem_1.MlKem1024,
};
class Kyber {
    getCtx(algo) {
        return new kyber_algorithms[algo]();
    }
    async get_keypair(algo, seed) {
        const ctx = this.getCtx(algo);
        const [public_key, secret_key] = await ctx.deriveKeyPair(seed);
        if (!public_key || !secret_key)
            throw new Error("Keypair generation failed");
        return { public_key, secret_key };
    }
    async get_keypair_hex(algo, seed) {
        const { public_key, secret_key } = await this.get_keypair(algo, seed);
        const toHex = (buf) => [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
        return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
    }
    async encapsulate(algo, public_key) {
        const ctx = this.getCtx(algo);
        const [cyphertext, shared_secret] = await ctx.encap(public_key);
        if (!cyphertext || !shared_secret)
            throw new Error("Encapsulation failed");
        return { cyphertext, shared_secret };
    }
    async decapsulate(algo, cyphertext, secret_key) {
        const ctx = this.getCtx(algo);
        const shared_secret = await ctx.decap(cyphertext, secret_key);
        if (!shared_secret)
            throw new Error("Decapsulation failed");
        return shared_secret;
    }
}
exports.Kyber = Kyber;
//# sourceMappingURL=kyber.js.map