#include <kamek.hpp>

namespace Pulsar {
namespace Race {

//Mushroom Glitch
kmWrite8(0x807BA077, 0x00000000);

//Rexcore Countdown
kmWrite32(0x805A225C, 0x38800001);

//Extend race online
kmWrite32(0x8053F3B8,0x3C600005);
kmWrite32(0x8053F3BC,0x38837E40);
kmWrite32(0x8053F478,0x4800000C); //6 Minute DC Disables

//Anti Online Penalized by B_squo
kmWrite32(0x80549218, 0x38600000);
kmWrite32(0x8054921c, 0x4e800020);

//WW Bubble Skip [Ro]
kmWrite8(0x80609647, 0x0000003C);
kmWrite8(0x8060964F, 0x0000001E);

//Remove Chadderz Button
kmWrite16(0x8064B982, 0x00000005);
kmWrite32(0x8064BA10, 0x60000000);
kmWrite32(0x8064BA38, 0x60000000);
kmWrite32(0x8064BA50, 0x60000000);
kmWrite32(0x8064BA5C, 0x60000000);
kmWrite16(0x8064BC12, 0x00000001);
kmWrite16(0x8064BC3E, 0x00000484);
kmWrite16(0x8064BC4E, 0x000010D7);
kmWrite16(0x8064BCB6, 0x00000484);
kmWrite16(0x8064BCC2, 0x000010D7);

//Floating Flibs [Stealth Steeler]
kmWrite32(0x808a5770, 0x00000000);
kmWrite32(0x808a5774, 0x00000000);

//No Bullet Bill Cancel When Touching Bottom of Rainbow Road [Ro]
kmWrite32(0x8059BE30, 0x60000000);

//Fix these fuckin boxes [Unnamed]
asmFunc ItemRespawn() {
loc_0x0:
  li r12, 0x45
  stw r12, 184(r27)
  stw r0, 176(r27)

}
kmCall(0x80828EDC, ItemRespawn);
}//namespace Race
}//namespace Pulsar