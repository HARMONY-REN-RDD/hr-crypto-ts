import dilithiumModulePromise from "dilithium-crystals-js";
declare const dilithium_algorithms: {
    readonly dilithium_2: 0;
    readonly dilithium_3: 1;
    readonly dilithium_5: 2;
};
type DilithiumAlgorithm = keyof typeof dilithium_algorithms;
interface KeyPair {
    public_key: Uint8Array;
    secret_key: Uint8Array;
}
interface HexKeyPair {
    public_key: string;
    secret_key: string;
}
declare class Dilithium {
    private static ctxPromise;
    static get_keypair(seed: Uint8Array, algo: DilithiumAlgorithm): Promise<KeyPair>;
    static get_keypair_hex(seed: Uint8Array, algo: DilithiumAlgorithm): Promise<HexKeyPair>;
    static sign(msg: Uint8Array, secret_key: Uint8Array, algo: DilithiumAlgorithm): Promise<Uint8Array>;
    static verify(signature: Uint8Array, msg: Uint8Array, public_key: Uint8Array, algo: DilithiumAlgorithm): Promise<boolean>;
}
export { Dilithium, dilithiumModulePromise, dilithium_algorithms };
export type { DilithiumAlgorithm, KeyPair, HexKeyPair };
//# sourceMappingURL=dilithium.d.ts.map