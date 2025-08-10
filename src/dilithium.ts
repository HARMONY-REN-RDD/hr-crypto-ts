import dilithiumModulePromise from "dilithium-crystals-js";

const dilithium_algorithms = {
  dilithium_2: 0,
  dilithium_3: 1,
  dilithium_5: 2,
} as const;

type DilithiumAlgorithm = keyof typeof dilithium_algorithms;

interface KeyPair {
  public_key: Uint8Array;
  secret_key: Uint8Array;
}

interface HexKeyPair {
  public_key: string;
  secret_key: string;
}

class Dilithium {
  private static ctxPromise = dilithiumModulePromise;

  static async get_keypair(seed: Uint8Array, algo: DilithiumAlgorithm): Promise<KeyPair> {
    if (!(seed instanceof Uint8Array)) throw new TypeError("Seed must be a Uint8Array");
    const ctx = await this.ctxPromise;
    const algo_id = dilithium_algorithms[algo];
    const { publicKey, privateKey } = ctx.generateKeys(algo_id, seed);
    if (!publicKey || !privateKey) throw new Error("Key generation failed");
    return { public_key: publicKey, secret_key: privateKey };
  }

  static async get_keypair_hex(seed: Uint8Array, algo: DilithiumAlgorithm): Promise<HexKeyPair> {
    const { public_key, secret_key } = await this.get_keypair(seed, algo);
    const toHex = (buf: Uint8Array) => [...buf].map(b => b.toString(16).padStart(2, "0")).join("");
    return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
  }

  static async sign(msg: Uint8Array, secret_key: Uint8Array, algo: DilithiumAlgorithm): Promise<Uint8Array> {
    if (!(msg instanceof Uint8Array) || !(secret_key instanceof Uint8Array))
      throw new TypeError("Message and secret key must be Uint8Array");
    const ctx = await this.ctxPromise;
    const algo_id = dilithium_algorithms[algo];
    const { signature } = ctx.sign(msg, secret_key, algo_id);
    if (!signature) throw new Error("Signing failed");
    return signature;
  }

  static async verify(signature: Uint8Array, msg: Uint8Array, public_key: Uint8Array, algo: DilithiumAlgorithm): Promise<boolean> {
    if (!(signature instanceof Uint8Array) || !(msg instanceof Uint8Array) || !(public_key instanceof Uint8Array))
      throw new TypeError("Signature, message, and public key must be Uint8Array");
    const ctx = await this.ctxPromise;
    const algo_id = dilithium_algorithms[algo];
    try {
      let status = ctx.verify(signature, msg, public_key, algo_id).result === 0;
      return status;
    } catch (e) {
      return false;
    }
  }
}

export { Dilithium };

export type { DilithiumAlgorithm, KeyPair, HexKeyPair };
