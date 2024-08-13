class Sealed {
    private readonly _sealed: never;

    constructor() {
        throw new Error("Cannot instantiate sealed class");
    }
}
class VersionEnum extends Sealed {
    static readonly V1_1 = "1.1";
    static readonly V1_2 = "1.2";
    static readonly V1_3 = "1.3";
}

console.log(VersionEnum.V1_1);