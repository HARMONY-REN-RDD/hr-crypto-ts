import { MlKem512, MlKem768, MlKem1024 } from "mlkem";
import { MlKemBase } from "mlkem/script/src/mlKemBase.js";

const kyber_algorithms = {
  kyber512: MlKem512,
  kyber768: MlKem768,
  kyber1024: MlKem1024,
} as const;

type KyberAlgorithm = keyof typeof kyber_algorithms;

class Kyber {
  private getCtx(algo: KyberAlgorithm): MlKemBase {
    return new kyber_algorithms[algo]();
  }

  async get_keypair(algo: KyberAlgorithm, seed: Uint8Array): Promise<{ public_key: Uint8Array; secret_key: Uint8Array }> {
    const ctx = this.getCtx(algo);
    const [public_key, secret_key] = await ctx.deriveKeyPair(seed);
    if (!public_key || !secret_key) throw new Error("Keypair generation failed");
    return { public_key, secret_key };
  }

  async get_keypair_hex(algo: KyberAlgorithm, seed: Uint8Array): Promise<{ public_key: string; secret_key: string }> {
    const { public_key, secret_key } = await this.get_keypair(algo, seed);
    const toHex = (buf: Uint8Array) => [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
    return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
  }

  async encapsulate(algo: KyberAlgorithm, public_key: Uint8Array): Promise<{
    cyphertext: Uint8Array;
    shared_secret: Uint8Array;
  }> {
    const ctx = this.getCtx(algo);
    const [cyphertext, shared_secret] = await ctx.encap(public_key);
    if (!cyphertext || !shared_secret) throw new Error("Encapsulation failed");
    return { cyphertext, shared_secret };
  }

  async decapsulate(algo: KyberAlgorithm, cyphertext: Uint8Array, secret_key: Uint8Array): Promise<Uint8Array> {
    const ctx = this.getCtx(algo);
    const shared_secret = await ctx.decap(cyphertext, secret_key);
    if (!shared_secret) throw new Error("Decapsulation failed");
    return shared_secret;
  }

}

export {
  Kyber
};

export type { KyberAlgorithm };
