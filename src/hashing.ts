import * as sha3 from '@noble/hashes/sha3';
import * as sha2 from '@noble/hashes/sha2';

const hashing_functions = {
  // SHA2
  sha2_256: sha2.sha256,
  sha2_512: sha2.sha512,
  
  // SHA3
  sha3_256: sha3.sha3_256,
  sha3_512: sha3.sha3_512,

} as const;

type HashAlgorithm = keyof typeof hashing_functions;

//const Hashing = {
//  hash(data: string, algo: HashAlgorithm): Uint8Array {;
//    return hashing_functions[algo](new TextEncoder().encode(data));
//  },
//
//  hash_hex(data: string, algo: HashAlgorithm): string {
//    return Buffer.from(this.hash(data, algo)).toString("hex");
//  }
//};

export {
  hashing_functions,
}

export type { HashAlgorithm };

