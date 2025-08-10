"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.dilithium_algorithms = exports.dilithiumModulePromise = exports.Dilithium = void 0;
const dilithium_crystals_js_1 = __importDefault(require("dilithium-crystals-js"));
exports.dilithiumModulePromise = dilithium_crystals_js_1.default;
const dilithium_algorithms = {
    dilithium_2: 0,
    dilithium_3: 1,
    dilithium_5: 2,
};
exports.dilithium_algorithms = dilithium_algorithms;
class Dilithium {
    static async get_keypair(seed, algo) {
        if (!(seed instanceof Uint8Array))
            throw new TypeError("Seed must be a Uint8Array");
        const ctx = await this.ctxPromise;
        const algo_id = dilithium_algorithms[algo];
        const { publicKey, privateKey } = ctx.generateKeys(algo_id, seed);
        if (!publicKey || !privateKey)
            throw new Error("Key generation failed");
        return { public_key: publicKey, secret_key: privateKey };
    }
    static async get_keypair_hex(seed, algo) {
        const { public_key, secret_key } = await this.get_keypair(seed, algo);
        const toHex = (buf) => [...buf].map(b => b.toString(16).padStart(2, "0")).join("");
        return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
    }
    static async sign(msg, secret_key, algo) {
        if (!(msg instanceof Uint8Array) || !(secret_key instanceof Uint8Array))
            throw new TypeError("Message and secret key must be Uint8Array");
        const ctx = await this.ctxPromise;
        const algo_id = dilithium_algorithms[algo];
        const { signature } = ctx.sign(msg, secret_key, algo_id);
        if (!signature)
            throw new Error("Signing failed");
        return signature;
    }
    static async verify(signature, msg, public_key, algo) {
        if (!(signature instanceof Uint8Array) || !(msg instanceof Uint8Array) || !(public_key instanceof Uint8Array))
            throw new TypeError("Signature, message, and public key must be Uint8Array");
        const ctx = await this.ctxPromise;
        const algo_id = dilithium_algorithms[algo];
        try {
            let status = ctx.verify(signature, msg, public_key, algo_id).result === 0;
            return status;
        }
        catch (e) {
            return false;
        }
    }
}
exports.Dilithium = Dilithium;
Dilithium.ctxPromise = dilithium_crystals_js_1.default;
//# sourceMappingURL=dilithium.js.map