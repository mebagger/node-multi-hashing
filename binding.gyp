{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "scryptn.c",
                "sha256d.c",
                "sha3/sph_sha2.c",
            ],
            'include_dirs': [
               "<!(node -e \"require('nan')\")"
             ],
            "cflags_cc": [
                "-std=c++0x"
            ],
        }
    ]
}
