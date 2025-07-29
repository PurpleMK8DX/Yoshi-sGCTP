#ifdef _WIIMMFI_

#include <kamek.hpp>

#undef _WIIMMFI_

/*
    This file was originally reverse engineered from code in LE-Code that was written by Leseratte/Wiimm.
    It's also went through several versions across different mods and patching systems, so contains some
    edits from Seeky, TheLordScruffy, and CLF78 at various points.
*/

extern "C"
{
    extern char Patch_LoginPrintHeader[]; // part of DWC::iLoginInit strings, the **** header, effectively unused so free and used for the header
    extern char Patch_WiimmfiURLs[];
    extern const char *Patch_AuthserverHosts[3];

    extern s32 DWC_AuthServer, SSL_Initialised;
    void NETSHA1Init();
    void NETSHA1Update();
    void NETSHA1GetDigest();
}

static u32 expectedHash[] = {0x0FFF1F07, 0x00E638C9, 0x49FBEFFA, 0x79022D3A, 0x84AB134F};

static asmFunc wiimmfiAsm1()
{
    ASM(
        nofralloc;

        // Original instruction
        cmpwi r3, 0;

        // Return workaround
        mflr r23;

        ble end;

        // r13 replacements
        lis r11, DWC_AuthServer @ha;
        lis r12, SSL_Initialised @ha;

        lwz r3, 0xC(sp);
        lwz r0, DWC_AuthServer @l(r11);
        cmpwi r0, 2;
        beq cont;

        stw r3, SSL_Initialised @l(r12);
        li r0, 2;
        stw r0, DWC_AuthServer @l(r11);
        b end;

        // Execute payload
        cont : addi r4, r3, 3;
        rlwinm r4, r4, 0, 0, 29;
        lbz r5, 0x0(r4);
        add r5, r4, r5;
        dcbf 0, r5;
        mtlr r5;
        blrl;

        // Original instruction
        end : li r3, -1;
        cmpwi r3, 0;

        // Return workaround
        mtlr r23;
        li r23, 0;
        blr;)
}

kmCall(0x800ee3a0, wiimmfiAsm1);

asmFunc wiimmfiAsm2()
{
    ASM(
        nofralloc;

        // Return workaround
        stwu sp, -8(sp);
        mflr r3;
        stw r3, 4(sp);

        lis r12, SSL_Initialised @ha;

        // Check if inited
        lwz r4, SSL_Initialised @l(r12);
        cmplwi r4, 1;
        ble nomatch;

        // Push stack
        stwu sp, -0x80(sp);

        // Call NETSHA1Init
        addi r3, sp, 0x20;
        bl NETSHA1Init;

        // Call NETSHA1Update
        addi r3, sp, 0x20;
        lis r12, SSL_Initialised @ha;
        lwz r4, SSL_Initialised @l(r12);
        li r5, 0x554;
        stw r5, 0xC4(r28);
        bl NETSHA1Update;

        // Call NETSHA1GetDigest
        addi r3, sp, 0x20;
        addi r4, sp, 0x10;
        bl NETSHA1GetDigest;

        // Setup loop
        lis r3, (expectedHash - 4) @h;
        ori r3, r3, (expectedHash - 4) @l;
        addi r4, sp, 0xC;
        li r5, 5;
        mtctr r5;

        // Loop it!
        loop : lwzu r5, 0x4(r3);
        lwzu r6, 0x4(r4);
        cmpw r6, r5;
        bne out;
        bdnz + loop;

        // Check if we found a match and pop the stack
        out :;
        cmpw r6, r5;
        addi sp, sp, 0x80;
        lis r12, SSL_Initialised @ha;
        lwz r4, SSL_Initialised @l(r12);
        beq end;

        // Return 0 otherwise
        nomatch : li r4, 0;

        end :
        // Return workaround
        lwz r3, 4(sp);
        mtlr r3;
        addi sp, sp, 8;
        blr;)
}

kmCall(0x801d4efc, wiimmfiAsm2);

static void patchURL(u32 offset, const char *string)
{
    strcpy(&Patch_WiimmfiURLs[offset], string);
}

static int stringPatch()
{
    strcpy(Patch_LoginPrintHeader, "Pulsar"); // set patcher name

    Patch_AuthserverHosts[0] = "http://ca.nas.wiimmfi.de/ca";
    Patch_AuthserverHosts[1] = "http://naswii.wiimmfi.de/ac";

    // Get path
    const char *path;
    switch (*(char *)0x80000003)
    {
    case 'E':
        Patch_AuthserverHosts[2] = "https://main.nas.wiimmfi.de/pe";
        break;
    case 'J':
        Patch_AuthserverHosts[2] = "https://main.nas.wiimmfi.de/pj";
        break;
    case 'P':
        Patch_AuthserverHosts[2] = "https://main.nas.wiimmfi.de/pp";
        break;
    case 'K':
        Patch_AuthserverHosts[2] = "https://main.nas.wiimmfi.de/pk";
        break;
    }

    patchURL(0xA8, "://naswii.wiimmfi.de/pr");
    patchURL(0x964, "wiimmfi.de");  // Available
    patchURL(0x10D4, "wiimmfi.de"); // GPCM
    patchURL(0x1AEC, "wiimmfi.de"); // GPSP
    patchURL(0x2C8D, "wiimmfi.de"); // Master
    patchURL(0x38A7, "wiimmfi.de"); // Natneg1
    patchURL(0x38C3, "wiimmfi.de"); // Natneg2
    patchURL(0x38DF, "wiimmfi.de"); // Natneg2
    patchURL(0x3A2F, "wiimmfi.de"); // MS
    patchURL(0x3AB3, "wiimmfi.de"); // SAKE

    return 0;
}
kmOnLoad(stringPatch);

// Force DWC_AUTHSERVER_DEBUG
kmWrite32(0x800ecaac, 0x3bc00000);

// Nop host header
kmWrite32(0x800ed868, 0x60000000);

#endif

#ifdef _NEWWFC_

#include <kamek.hpp>

#undef _NEWWFC_

extern "C"
{
    extern s32 Patch_LoginPrintHeader;
    char *hash;
    char *code;
    char *gs;
    char *w0;
    char *pul2;
    
    static u32 rmce[] = {0x00000000, 0x00000000, 0x801d8f58, 0x801d91bc, 0x801d9258, 0x80286aa4, 0x802ed938};
    static u32 rmcj[] = {0x00000000, 0x00000000, 0x801D8F18, 0x801D917C, 0x801D9218, 0x8028A784, 0x802F1638};
    static u32 rmcp[] = {0x00000000, 0x00000000, 0x801D8FF8, 0x801D925C, 0x801D92F8, 0x8028ADE4, 0x802F1CB8};
    static u32 rmck[] = {0x00000000, 0x00000000, 0x801D9354, 0x801D95B8, 0x801D9654, 0x80278DD4, 0x802DFCB8};
    char *gamever = "RMCXDa2\0\0\0\0\0\x60\0\0\0";
    // u32 *destination = nullptr; // Destination address (example address)
}

static void writemem32(u32 offset, u32 value)
{
    memcpy((void *)offset, &value, sizeof(u32));
}

static int patch()
{

    static u32 data[] = {0x4800007C, 0x35306434, 0x38623033, 0x36326537,
                         0x33383763, 0x64353739, 0x37326162, 0x31643534,
                         0x35333239}; // payload hash

    u32 offsets[7] = {0};

    u32 codedata[] = {
        0x48000088,
        0x3FE0800F,
        // different
        0x00000000, // 0x3BFFDE0C, //2*4

        0x8061000C,
        0x38800F2A,
        0x38A1001C,
        0x48002D59,
        0x3861001C,
        0x389FFFDC,
        // diferent
        0x00000000, // 0x4BF24721,//9*4

        0x2C030000,
        0x4182000C,
        0x3800AE5A,
        0x48000A34,
        0x8061000C,
        0x38630002,
        0x389F0000,

        0x00000000, //0x80AD973C JPE, //issue, different in kor 17*4

        0x38A559E0,
        0x7C6903A6,
        0x4E800421,
        0x48000A68,
    };

    u32 *addr1 = (u32 *)codedata[2];
    u32 *addr2 = (u32 *)codedata[9];
    u32 *addr3 = (u32 *)codedata[17];
    // Get path
    // const char *path;
    switch (*(char *)0x80000003)
    {
    case 'E':
        gamever = "RMCEDf0\0\0\0\0\0";
        memcpy(offsets, rmce, sizeof(rmce));
        gs = (char *)0x80276a25;
        w0 = (char *)0x802760ec;
        code = (char *)0x800edff8;
        hash = (char *)0x800EDDE4;
        writemem32(0x800EE308, 0x4bfffcf4); // branches C60EE308 800EDFFC
        writemem32(0x800D1478, 0x480001f4); // branches C60D1478 800D166C
        codedata[2] = 0x3BFFDE0C;
        codedata[9] = 0x4BF24721;
        codedata[17] = 0x80AD973C;
        break;
    case 'J':
        gamever = "RMCJDf0\0\0\0\0\0";
        memcpy(offsets, rmcj, sizeof(rmcj));
        gs = (char *)0x8027A705;
        w0 = (char *)0x80279DCC;
        code = (char *)0x800EDFB8;
        hash = (char *)0x800EDDA4;
        writemem32(0x800ee2c8, 0x4bfffcf4); // C60EE2C8 800EDFBC 4B FF FC F4
        writemem32(0x800D1438, 0x480001f4); // C60D1438 800D162C 48 00 01 F4
        codedata[2] = 0x3BFFDDCC;           // fix
        codedata[9] = 0x4BF251E5;
        codedata[17] = 0x80AD973C;
        break;
    case 'P':
        gamever = "RMCPDf0\0\0\0\0\0";
        memcpy(offsets, rmcp, sizeof(rmcp));
        gs = (char *)0x8027A42C;
        w0 = (char *)0x8027A42C;
        code = (char *)0x800EE098;
        hash = (char *)0x800EDE84;
        writemem32(0x800EE3a8, 0x4bfffcf4); // C60EE3A8 800EE09C  4BFFFCF4
        writemem32(0x800D1518, 0x480001f4); // C60D1518 800D170C 480001F4
        codedata[2] = 0x3BFFDEAC;
        codedata[9] = 0x4BF251E1;
        codedata[17] = 0x80AD973C;
        break;
    case 'K':
        gamever = "RMCKDf0\0\0\0\0\0";
        memcpy(offsets, rmck, sizeof(rmck));
        gs = (char *)0x80268C15;
        w0 = (char *)0x802682DC;
        code = (char *)0x800EE110;
        hash = (char *)0x800EDEFC;
        writemem32(0x800EE420, 0x4bfffcf4); // C60EE420 800EE114 4B FF FC F4
        writemem32(0x800D1578, 0x480001f4); // C60D1578 800D176C 48 00 01 F4
        codedata[2] = 0x3BFFDF24;
        codedata[9] = 0x4BF251D1;
        codedata[17] = 0x80AD975C;
        break;
    }
    pul2 = (char *)0x800017CC;
    memcpy(code, codedata, sizeof(codedata));
    memcpy(hash, data, sizeof(data));
    memcpy(hash + sizeof(data), offsets, sizeof(offsets));
    memcpy(hash + sizeof(data) + sizeof(offsets), gamever, 12);
    strcpy(gs, "gs.newwfc.xyz");
    strcpy(w0, "://nas.newwfc.xyz/w0");
    strcpy(pul2, "PUL2");

    return 0;
};

kmOnLoad(patch);

#endif

