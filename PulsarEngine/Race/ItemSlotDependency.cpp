#include <kamek.hpp>
#include <Info.hpp>
#include <MarioKartWii/Archive/ArchiveMgr.hpp>
#include <MarioKartWii/Item/ItemManager.hpp>
#include <MarioKartWii/Item/Obj/Kumo.hpp>
#include <MarioKartWii/Kart/KartMovement.hpp>
#include <MarioKartWii/Race/RaceData.hpp>
#include <SlotExpansion/CupsConfig.hpp>
#include <PulsarSystem.hpp>
//#include <VP.hpp>

namespace Pulsar {
namespace Race{
static void *GetCustomItemSlot(ArchiveMgr *archive, ArchiveSource type, const char *name, u32 *length){
	const u8 playerCount = Racedata::sInstance->GetPlayerCount();
    if(System::sInstance->IsContext(PULSAR_MEGATC)){
        name = "ItemSlotRex.bin";
    }
    if(System::sInstance->IsContext(PULSAR_REGS)){
        name = "ItemSlot.bin";
    }
    if (playerCount > 6){
    name = "ItemSlot.bin";
    }
    /*else if (gamemode == GAMEMODE_BBB){
        name = "ItemSlot2.bin";
    }*/
    return archive->GetFile(type, name, length);
}
kmCall(0x807bb128, GetCustomItemSlot);
kmCall(0x807bb030, GetCustomItemSlot);
kmCall(0x807bb200, GetCustomItemSlot);
kmCall(0x807bb53c, GetCustomItemSlot);
kmCall(0x807bbb58, GetCustomItemSlot);
} // namespace Race
} // namespace VP