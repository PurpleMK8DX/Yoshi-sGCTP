#include <MarioKartWii/Item/ItemManager.hpp>
#include <MarioKartWii/Item/Obj/Kumo.hpp>
#include <MarioKartWii/Kart/KartMovement.hpp>
#include <Info.hpp>


namespace yoshpackDX {
namespace Race {
kmCallDefAsm(0x805793AC) {
loc_0x0:
  lwz r4, 0(r28)
  lwz r29, 36(r4)
  cmpwi r29, 0x0
  beq- loc_0x28
  lwz r3, 4(r4)
  lwz r3, 12(r3)
  rlwinm. r3, r3, 0, 16, 16
  beq- loc_0x28
  lis r0, 0x41F0
  stw r0, 288(r29)

loc_0x28:
    blr;
}

}//namespace Race
}//namespace Pulsar