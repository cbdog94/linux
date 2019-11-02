Linux kernel
============

[![Latest release][release_badge]][release_url]

Introduction
---

This repo modified the linux kernel for supporting some custom features. Compared with the original version, it mainly added a domain set module similar to ipset for ebtables and extended the ipset and xt_comment for supporting ebtables.

The modified parts are listed below:
```
├── include/
│   ├── linux/
│   │   └── netfilter/
│   │       └── dset/
│   └── uapi/
│       └── linux/
│           └── netfilter/
│               ├── dset/
│               └── nfnetlink.h     // Add socket protocol for dset
└── net/
    └── netfilter/
        ├── dset/
        ├── Kconfig
        ├── Makefile
        ├── xt_comment.c    // Add comment match for ebtables
        ├── xt_dset.c       // Add dset match for ebtables
        └── xt_set.c        // Add set match for ebtables
```

 [release_badge]: https://img.shields.io/github/release/cbdog94/linux.svg
 [release_url]: https://github.com/cbdog94/linux/releases/latest