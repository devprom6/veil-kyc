// Minimal type declarations for circomlibjs 0.1.7 (async builders).
declare module "circomlibjs" {
  // Field elements in the wasm-backed field are Uint8Array subclasses.
  export type FieldElement = Uint8Array;

  export interface PoseidonHash {
    (inputs: (bigint | number | string | Uint8Array)[]): Uint8Array;
    F: {
      e(x: unknown): FieldElement;
      toObject(x: unknown): bigint;
    };
  }

  export interface EdDSASignature {
    R8: [FieldElement, FieldElement];
    S: bigint;
  }

  export interface EdDSA {
    F: {
      e(x: unknown): FieldElement;
      toObject(x: unknown): bigint;
    };
    prv2pub(prv: Uint8Array): [FieldElement, FieldElement];
    signPoseidon(prv: Uint8Array, msg: unknown): EdDSASignature;
    verifyPoseidon(
      msg: unknown,
      sig: EdDSASignature,
      A: [FieldElement, FieldElement],
    ): boolean;
  }

  export function buildPoseidon(): Promise<PoseidonHash>;
  export function buildEddsa(): Promise<EdDSA>;
}
