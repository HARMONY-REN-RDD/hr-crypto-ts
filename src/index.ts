import { hkdf } from '@noble/hashes/hkdf';

import { Kyber, KyberAlgorithm } from './kyber';
import { hashing_functions, HashAlgorithm } from "./hashing";
import { Dilithium, DilithiumAlgorithm, HexKeyPair, KeyPair } from './dilithium';

export default class HarmonyCrypto {
  static hash(data: string, algo: HashAlgorithm): Uint8Array {
    return hashing_functions[algo](new TextEncoder().encode(data));
  }
  
  static hash_hex(data: string, algo: HashAlgorithm): string {
    const bytes = this.hash(data, algo);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  static async hkdf_derive(seed: Uint8Array, salt: Uint8Array, info: string, length: number): Promise<Uint8Array> {
    return hkdf(hashing_functions.sha3_256, seed, salt, new TextEncoder().encode(info), length);
  }

  async get_kyber_kypair(
    algo: KyberAlgorithm,
    seed: Uint8Array,
    info?: string
  ): Promise<{ public_key: Uint8Array; secret_key: Uint8Array }> {
    const infoStr = info ? ` ${info}` : '';
    const derivedSeed = hkdf(
      hashing_functions.sha3_512,
      seed,
      new Uint8Array(0),
      new TextEncoder().encode(`${algo}${infoStr}`),
      64
    );
    return await new Kyber().get_keypair(algo, derivedSeed);
  }

  async get_kyber_keypair_hex(algo: KyberAlgorithm, seed: Uint8Array): Promise<{ public_key: string; secret_key: string }> {
    const { public_key, secret_key } = await this.get_kyber_kypair(algo, seed);
    const toHex = (buf: Uint8Array) => [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
    return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
  }

  async kyber_encapsulate(algo: KyberAlgorithm, public_key: Uint8Array): Promise<{
    cyphertext: Uint8Array;
    shared_secret: Uint8Array;
  }> {
    return await new Kyber().encapsulate(algo, public_key);
  }

  async kyber_decapsulate(algo: KyberAlgorithm, msg: Uint8Array, secret_key: Uint8Array): Promise<Uint8Array> {
    return await new Kyber().decapsulate(algo, msg, secret_key);
  }

  async get_dilithium_keypair(algo: DilithiumAlgorithm, seed: Uint8Array, info?: string): Promise<KeyPair> {
    const infoStr = info ? ` ${info}` : '';
    const derivedSeed = hkdf(
      hashing_functions.sha3_512,
      seed,
      new Uint8Array(0),
      new TextEncoder().encode(`${algo}${infoStr}`),
      32
    );
    return await Dilithium.get_keypair(derivedSeed, algo);
  }

  async get_dilithium_keypair_hex(seed: Uint8Array, algo: DilithiumAlgorithm): Promise<HexKeyPair> {
    const { public_key, secret_key } = await this.get_dilithium_keypair(algo, seed);
    const toHex = (buf: Uint8Array) => [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
    return { public_key: toHex(public_key), secret_key: toHex(secret_key) };
  }

  async dilithium_sign(msg: Uint8Array, secret_key: Uint8Array, algo: DilithiumAlgorithm): Promise<Uint8Array> {
    return await Dilithium.sign(msg, secret_key, algo);
  }

  async dilithium_verify(signature: Uint8Array, msg: Uint8Array, public_key: Uint8Array, algo: DilithiumAlgorithm): Promise<boolean> {
    return await Dilithium.verify(signature, msg, public_key, algo);
  }
}

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
  console.log(shared_secret.length  // should be true
    === decapsulated.length && shared_secret.every((v, i) => v === decapsulated[i]));
}

// main();
