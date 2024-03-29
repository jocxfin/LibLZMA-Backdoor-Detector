# LibLZMA-Backdoor-Detector

# Technical explanation of the xz/liblzma backdoor exploit

The exploit discovered within the `xz` package, specifically targeting the `liblzma` library, exemplifies a sophisticated and multi-layered attack against Linux systems.

## Initial Compromise

The exploit begins with a compromised distribution of the `xz` tarballs, where malicious code is inserted outside of the official source repository. This insertion targets specific versions of the package (5.6.0 and 5.6.1) and leverages obfuscated scripts executed during the `configure` process of installation or building from source.

### Obfuscated Script Execution

A critical component of the exploit involves an obfuscated script that is executed at the end of the `configure` process. This script is designed to inject malicious instructions into the build process, specifically modifying the `Makefile` within `$builddir/src/liblzma/` to include references to corrupted `.xz` test files containing part of the exploit code.

## Key Components of the Exploit

1. **Modified Makefile**: The obfuscated script alters the `Makefile` to execute additional, compromised scripts. It points to specially crafted `.xz` files that when decompressed, execute shell commands or further malicious payloads.

2. **Conditional Execution**: The exploit includes logic to check for specific system conditions before activating. These checks are designed to ensure the exploit only triggers under optimal conditions to avoid detection. Conditions checked include system architecture, compiler presence (gcc with GNU linker), and certain environment variables indicative of a developer or a debugging environment.

3. **Influence on SSH Server**: Despite OpenSSH not directly using `liblzma`, certain Linux distributions have added dependencies (e.g., through systemd notification support), making SSH servers indirectly vulnerable. The exploit can cause noticeable slowdowns in SSH login processes, serving as a symptom of the exploit's presence.

## Exploit Activation and SSH Impact

Upon successful modification of the `liblzma` build process, the compromised library affects systems in subtle yet significant ways:

- **SSH Connection Delays**: With the backdoored `liblzma` installed, SSH connections experience notable delays. This slowdown is attributed to additional processing introduced by the exploit, affecting systems even where SSH does not directly utilize `liblzma`.

- **ifunc Resolver Manipulation**: The exploit replaces the `ifunc` resolvers for `crc32` and `crc64` with malicious code. This early execution control allows for further manipulation of system functions and libraries.

- **Global Offset Table (GOT) Manipulation**: By intercepting and modifying symbol resolution, the exploit directs certain function calls to execute malicious payloads. Notably, it alters the handling of `RSA_public_decrypt` to redirect to exploit code, potentially allowing unauthorized access or code execution.

## Conditions for Exploit Triggering

The exploit's activation is contingent upon a set of specific environmental conditions:

- Targeting only x86-64 Linux systems.
- Requirement for the build process to utilize gcc and the GNU linker.
- Execution within a Debian or RPM package build environment.
- Absence of certain debugging environment variables (`LD_DEBUG`, `LD_PROFILE`).
- Presence of specific `LANG` environment variables.

## Conclusion and Implications

This exploit showcases the complexity of supply chain attacks, where vulnerabilities can be introduced at any stage of software distribution. It underlines the necessity for rigorous security checks throughout the software build and distribution processes. Additionally, it highlights the critical need for maintaining updated and secure systems, alongside a cautious examination of third-party dependencies.

I created this article after reading the email of the user https://github.com/anarazel which can be found here: https://www.openwall.com/lists/oss-security/2024/03/29/4. 

I also created a modified version of the detection script the user https://github.com/vegard has made. The script simplifies its SSH delay test to enhance user-friendliness, ensuring it's broadly accessible for vulnerability detection. This approach strikes a balance between thorough security scanning and ease of use for users of all technical levels.
