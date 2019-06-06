/* packet-sysex.c
 *
 * MIDI SysEx dissector
 * Tomasz Mon 2012
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

void proto_register_sysex(void);
void proto_reg_handoff_sysex(void);

/* protocols and header fields */
static int proto_sysex = -1;
static int hf_sysex_message_start = -1;
static int hf_sysex_manufacturer_id = -1;
static int hf_sysex_three_byte_manufacturer_id = -1;
static int hf_sysex_message_eox = -1;

static gint ett_sysex = -1;

static dissector_handle_t sysex_digitech_handle;

static expert_field ei_sysex_message_start_byte = EI_INIT;
static expert_field ei_sysex_message_end_byte = EI_INIT;
static expert_field ei_sysex_undecoded = EI_INIT;

#define SYSEX_MANUFACTURER_DOD 0x000010

/* Manufacturer and Extended Manufacturer IDs as of April 2019
 * https://www.midi.org/specifications-old/item/manufacturer-id-numbers
 */
static const value_string sysex_manufacturer_id_vals[] = {
    {0x01, "Sequential"},
    {0x02, "IDP"},
    {0x03, "Voyetra Turtle Beach, Inc."},
    {0x04, "Moog Music"},
    {0x05, "Passport Designs"},
    {0x06, "Lexicon Inc."},
    {0x07, "Kurzweil / Young Chang"},
    {0x08, "Fender"},
    {0x09, "MIDI9"},
    {0x0A, "AKG Acoustics"},
    {0x0B, "Voyce Music"},
    {0x0C, "WaveFrame (Timeline)"},
    {0x0D, "ADA Signal Processors, Inc."},
    {0x0E, "Garfield Electronics"},
    {0x0F, "Ensoniq"},
    {0x10, "Oberheim / Gibson Labs"},
    {0x11, "Apple, Inc."},
    {0x12, "Grey Matter Response"},
    {0x13, "Digidesign Inc."},
    {0x14, "Palmtree Instruments"},
    {0x15, "JLCooper Electronics"},
    {0x16, "Lowrey Organ Company"},
    {0x17, "Adams-Smith"},
    {0x18, "E-mu"},
    {0x19, "Harmony Systems"},
    {0x1A, "ART"},
    {0x1B, "Baldwin"},
    {0x1C, "Eventide"},
    {0x1D, "Inventronics"},
    {0x1E, "Key Concepts"},
    {0x1F, "Clarity"},
    {0x20, "Passac"},
    {0x21, "Proel Labs (SIEL)"},
    {0x22, "Synthaxe (UK)"},
    {0x23, "Stepp"},
    {0x24, "Hohner"},
    {0x25, "Twister"},
    {0x26, "Ketron s.r.l."},
    {0x27, "Jellinghaus MS"},
    {0x28, "Southworth Music Systems"},
    {0x29, "PPG (Germany)"},
    {0x2A, "JEN"},
    {0x2B, "Solid State Logic Organ Systems"},
    {0x2C, "Audio Veritrieb-P. Struven"},
    {0x2D, "Neve"},
    {0x2E, "Soundtracs Ltd."},
    {0x2F, "Elka"},
    {0x30, "Dynacord"},
    {0x31, "Viscount International Spa (Intercontinental Electronics)"},
    {0x32, "Drawmer"},
    {0x33, "Clavia Digital Instruments"},
    {0x34, "Audio Architecture"},
    {0x35, "Generalmusic Corp SpA"},
    {0x36, "Cheetah Marketing"},
    {0x37, "C.T.M."},
    {0x38, "Simmons UK"},
    {0x39, "Soundcraft Electronics"},
    {0x3A, "Steinberg Media Technologies AG"},
    {0x3B, "Wersi Gmbh"},
    {0x3C, "AVAB Niethammer AB"},
    {0x3D, "Digigram"},
    {0x3E, "Waldorf Electronics GmbH"},
    {0x3F, "Quasimidi"},
    {0x40, "Kawai Musical Instruments MFG. CO. Ltd"},
    {0x41, "Roland Corporation"},
    {0x42, "Korg Inc."},
    {0x43, "Yamaha Corporation"},
    {0x44, "Casio Computer Co. Ltd"},
    {0x46, "Kamiya Studio Co. Ltd"},
    {0x47, "Akai Electric Co. Ltd."},
    {0x48, "Victor Company of Japan, Ltd."},
    {0x4B, "Fujitsu Limited"},
    {0x4C, "Sony Corporation"},
    {0x4E, "Teac Corporation"},
    {0x50, "Matsushita Electric Industrial Co. , Ltd"},
    {0x51, "Fostex Corporation"},
    {0x52, "Zoom Corporation"},
    {0x54, "Matsushita Communication Industrial Co., Ltd."},
    {0x55, "Suzuki Musical Instruments MFG. Co., Ltd."},
    {0x56, "Fuji Sound Corporation Ltd."},
    {0x57, "Acoustic Technical Laboratory, Inc."},
    {0x59, "Faith, Inc."},
    {0x5A, "Internet Corporation"},
    {0x5C, "Seekers Co. Ltd."},
    {0x5F, "SD Card Association"},
    /* Three special IDs specified in MIDI 1.0 Detailed Specification */
    {0x7D, "Educational/Non-Commercial Use"},
    {0x7E, "Non-Real Time Universal System Exlusive"},
    {0x7F, "Real Time Universal System Exclusive"},
    {0,NULL}
};
static value_string_ext sysex_manufacturer_id_vals_ext =
    VALUE_STRING_EXT_INIT(sysex_manufacturer_id_vals);

static const value_string sysex_extended_manufacturer_id_vals[] = {
    {0x000001, "Time/Warner Interactive"},
    {0x000002, "Advanced Gravis Comp. Tech Ltd."},
    {0x000003, "Media Vision"},
    {0x000004, "Dornes Research Group"},
    {0x000005, "K-Muse"},
    {0x000006, "Stypher"},
    {0x000007, "Digital Music Corp."},
    {0x000008, "IOTA Systems"},
    {0x000009, "New England Digital"},
    {0x00000A, "Artisyn"},
    {0x00000B, "IVL Technologies Ltd."},
    {0x00000C, "Southern Music Systems"},
    {0x00000D, "Lake Butler Sound Company"},
    {0x00000E, "Alesis Studio Electronics"},
    {0x00000F, "Sound Creation"},
    {0x000010, "DOD Electronics Corp."},
    {0x000011, "Studer-Editech"},
    {0x000012, "Sonus"},
    {0x000013, "Temporal Acuity Products"},
    {0x000014, "Perfect Fretworks"},
    {0x000015, "KAT Inc."},
    {0x000016, "Opcode Systems"},
    {0x000017, "Rane Corporation"},
    {0x000018, "Anadi Electronique"},
    {0x000019, "KMX"},
    {0x00001A, "Allen & Heath Brenell"},
    {0x00001B, "Peavey Electronics"},
    {0x00001C, "360 Systems"},
    {0x00001D, "Spectrum Design and Development"},
    {0x00001E, "Marquis Music"},
    {0x00001F, "Zeta Systems"},
    {0x000020, "Axxes (Brian Parsonett)"},
    {0x000021, "Orban"},
    {0x000022, "Indian Valley Mfg."},
    {0x000023, "Triton"},
    {0x000024, "KTI"},
    {0x000025, "Breakaway Technologies"},
    {0x000026, "Leprecon / CAE Inc."},
    {0x000027, "Harrison Systems Inc."},
    {0x000028, "Future Lab/Mark Kuo"},
    {0x000029, "Rocktron Corporation"},
    {0x00002A, "PianoDisc"},
    {0x00002B, "Cannon Research Group"},
    {0x00002C, "Reserved"},
    {0x00002D, "Rodgers Instrument LLC"},
    {0x00002E, "Blue Sky Logic"},
    {0x00002F, "Encore Electronics"},
    {0x000030, "Uptown"},
    {0x000031, "Voce"},
    {0x000032, "CTI Audio, Inc. (Musically Intel. Devs.)"},
    {0x000033, "S3 Incorporated"},
    {0x000034, "Broderbund / Red Orb"},
    {0x000035, "Allen Organ Co."},
    {0x000036, "Reserved"},
    {0x000037, "Music Quest"},
    {0x000038, "Aphex"},
    {0x000039, "Gallien Krueger"},
    {0x00003A, "IBM"},
    {0x00003B, "Mark Of The Unicorn"},
    {0x00003C, "Hotz Corporation"},
    {0x00003D, "ETA Lighting"},
    {0x00003E, "NSI Corporation"},
    {0x00003F, "Ad Lib, Inc."},
    {0x000040, "Richmond Sound Design"},
    {0x000041, "Microsoft"},
    {0x000042, "Mindscape (Software Toolworks)"},
    {0x000043, "Russ Jones Marketing / Niche"},
    {0x000044, "Intone"},
    {0x000045, "Advanced Remote Technologies"},
    {0x000046, "White Instruments"},
    {0x000047, "GT Electronics/Groove Tubes"},
    {0x000048, "Pacific Research & Engineering"},
    {0x000049, "Timeline Vista, Inc."},
    {0x00004A, "Mesa Boogie Ltd."},
    {0x00004B, "FSLI"},
    {0x00004C, "Sequoia Development Group"},
    {0x00004D, "Studio Electronics"},
    {0x00004E, "Euphonix, Inc"},
    {0x00004F, "InterMIDI, Inc."},
    {0x000050, "MIDI Solutions Inc."},
    {0x000051, "3DO Company"},
    {0x000052, "Lightwave Research / High End Systems"},
    {0x000053, "Micro-W Corporation"},
    {0x000054, "Spectral Synthesis, Inc."},
    {0x000055, "Lone Wolf"},
    {0x000056, "Studio Technologies Inc."},
    {0x000057, "Peterson Electro-Musical Product, Inc."},
    {0x000058, "Atari Corporation"},
    {0x000059, "Marion Systems Corporation"},
    {0x00005A, "Design Event"},
    {0x00005B, "Winjammer Software Ltd."},
    {0x00005C, "AT&T Bell Laboratories"},
    {0x00005D, "Reserved"},
    {0x00005E, "Symetrix"},
    {0x00005F, "MIDI the World"},
    {0x000060, "Spatializer"},
    {0x000061, "Micros 'N MIDI"},
    {0x000062, "Accordians International"},
    {0x000063, "EuPhonics (now 3Com)"},
    {0x000064, "Musonix"},
    {0x000065, "Turtle Beach Systems (Voyetra)"},
    {0x000066, "Loud Technologies / Mackie"},
    {0x000067, "Compuserve"},
    {0x000068, "BEC Technologies"},
    {0x000069, "QRS Music Inc"},
    {0x00006A, "P.G. Music"},
    {0x00006B, "Sierra Semiconductor"},
    {0x00006C, "EpiGraf"},
    {0x00006D, "Electronics Diversified Inc"},
    {0x00006E, "Tune 1000"},
    {0x00006F, "Advanced Micro Devices"},
    {0x000070, "Mediamation"},
    {0x000071, "Sabine Musical Mfg. Co. Inc."},
    {0x000072, "Woog Labs"},
    {0x000073, "Micropolis Corp"},
    {0x000074, "Ta Horng Musical Instrument"},
    {0x000075, "e-Tek Labs (Forte Tech)"},
    {0x000076, "Electro-Voice"},
    {0x000077, "Midisoft Corporation"},
    {0x000078, "QSound Labs"},
    {0x000079, "Westrex"},
    {0x00007A, "Nvidia"},
    {0x00007B, "ESS Technology"},
    {0x00007C, "Media Trix Peripherals"},
    {0x00007D, "Brooktree Corp"},
    {0x00007E, "Otari Corp"},
    {0x00007F, "Key Electronics, Inc."},
    {0x000100, "Shure Incorporated"},
    {0x000101, "AuraSound"},
    {0x000102, "Crystal Semiconductor"},
    {0x000103, "Conexant (Rockwell)"},
    {0x000104, "Silicon Graphics"},
    {0x000105, "M-Audio (Midiman)"},
    {0x000106, "PreSonus"},
    {0x000108, "Topaz Enterprises"},
    {0x000109, "Cast Lighting"},
    {0x00010A, "Microsoft"},
    {0x00010B, "Sonic Foundry"},
    {0x00010C, "Line 6 (Fast Forward) (Yamaha)"},
    {0x00010D, "Beatnik Inc"},
    {0x00010E, "Van Koevering Company"},
    {0x00010F, "Altech Systems"},
    {0x000110, "S & S Research"},
    {0x000111, "VLSI Technology"},
    {0x000112, "Chromatic Research"},
    {0x000113, "Sapphire"},
    {0x000114, "IDRC"},
    {0x000115, "Justonic Tuning"},
    {0x000116, "TorComp Research Inc."},
    {0x000117, "Newtek Inc."},
    {0x000118, "Sound Sculpture"},
    {0x000119, "Walker Technical"},
    {0x00011A, "Digital Harmony (PAVO)"},
    {0x00011B, "InVision Interactive"},
    {0x00011C, "T-Square Design"},
    {0x00011D, "Nemesys Music Technology"},
    {0x00011E, "DBX Professional (Harman Intl)"},
    {0x00011F, "Syndyne Corporation"},
    {0x000120, "Bitheadz"},
    {0x000121, "Cakewalk Music Software"},
    {0x000122, "Analog Devices"},
    {0x000123, "National Semiconductor"},
    {0x000124, "Boom Theory / Adinolfi Alternative Percussion"},
    {0x000125, "Virtual DSP Corporation"},
    {0x000126, "Antares Systems"},
    {0x000127, "Angel Software"},
    {0x000128, "St Louis Music"},
    {0x000129, "Passport Music Software LLC (Gvox)"},
    {0x00012A, "Ashley Audio Inc."},
    {0x00012B, "Vari-Lite Inc."},
    {0x00012C, "Summit Audio Inc."},
    {0x00012D, "Aureal Semiconductor Inc."},
    {0x00012E, "SeaSound LLC"},
    {0x00012F, "U.S. Robotics"},
    {0x000130, "Aurisis Research"},
    {0x000131, "Nearfield Research"},
    {0x000132, "FM7 Inc"},
    {0x000133, "Swivel Systems"},
    {0x000134, "Hyperactive Audio Systems"},
    {0x000135, "MidiLite (Castle Studios Productions)"},
    {0x000136, "Radikal Technologies"},
    {0x000137, "Roger Linn Design"},
    {0x000138, "TC-Helicon Vocal Technologies"},
    {0x000139, "Event Electronics"},
    {0x00013A, "Sonic Network Inc"},
    {0x00013B, "Realtime Music Solutions"},
    {0x00013C, "Apogee Digital"},
    {0x00013D, "Classical Organs, Inc."},
    {0x00013E, "Microtools Inc."},
    {0x00013F, "Numark Industries"},
    {0x000140, "Frontier Design Group, LLC"},
    {0x000141, "Recordare LLC"},
    {0x000142, "Starr Labs"},
    {0x000143, "Voyager Sound Inc."},
    {0x000144, "Manifold Labs"},
    {0x000145, "Aviom Inc."},
    {0x000146, "Mixmeister Technology"},
    {0x000147, "Notation Software"},
    {0x000148, "Mercurial Communications"},
    {0x000149, "Wave Arts"},
    {0x00014A, "Logic Sequencing Devices"},
    {0x00014B, "Axess Electronics"},
    {0x00014C, "Muse Research"},
    {0x00014D, "Open Labs"},
    {0x00014E, "Guillemot Corp"},
    {0x00014F, "Samson Technologies"},
    {0x000150, "Electronic Theatre Controls"},
    {0x000151, "Blackberry (RIM)"},
    {0x000152, "Mobileer"},
    {0x000153, "Synthogy"},
    {0x000154, "Lynx Studio Technology Inc."},
    {0x000155, "Damage Control Engineering LLC"},
    {0x000156, "Yost Engineering, Inc."},
    {0x000157, "Brooks & Forsman Designs LLC / DrumLite"},
    {0x000158, "Infinite Response"},
    {0x000159, "Garritan Corp"},
    {0x00015A, "Plogue Art et Technologie, Inc"},
    {0x00015B, "RJM Music Technology"},
    {0x00015C, "Custom Solutions Software"},
    {0x00015D, "Sonarcana LLC / Highly Liquid"},
    {0x00015E, "Centrance"},
    {0x00015F, "Kesumo LLC"},
    {0x000160, "Stanton (Gibson Brands)"},
    {0x000161, "Livid Instruments"},
    {0x000162, "First Act / 745 Media"},
    {0x000163, "Pygraphics, Inc."},
    {0x000164, "Panadigm Innovations Ltd"},
    {0x000165, "Avedis Zildjian Co"},
    {0x000166, "Auvital Music Corp"},
    {0x000167, "You Rock Guitar (was: Inspired Instruments)"},
    {0x000168, "Chris Grigg Designs"},
    {0x000169, "Slate Digital LLC"},
    {0x00016A, "Mixware"},
    {0x00016B, "Social Entropy"},
    {0x00016C, "Source Audio LLC"},
    {0x00016D, "Ernie Ball / Music Man"},
    {0x00016E, "Fishman"},
    {0x00016F, "Custom Audio Electronics"},
    {0x000170, "American Audio/DJ"},
    {0x000171, "Mega Control Systems"},
    {0x000172, "Kilpatrick Audio"},
    {0x000173, "iConnectivity"},
    {0x000174, "Fractal Audio"},
    {0x000175, "NetLogic Microsystems"},
    {0x000176, "Music Computing"},
    {0x000177, "Nektar Technology Inc"},
    {0x000178, "Zenph Sound Innovations"},
    {0x000179, "DJTechTools.com"},
    {0x00017A, "Rezonance Labs"},
    {0x00017B, "Decibel Eleven"},
    {0x00017C, "CNMAT"},
    {0x00017D, "Media Overkill"},
    {0x00017E, "Confusion Studios"},
    {0x00017F, "moForte Inc"},
    {0x000200, "Miselu Inc"},
    {0x000201, "Amelia's Compass LLC"},
    {0x000202, "Zivix LLC"},
    {0x000203, "Artiphon"},
    {0x000204, "Synclavier Digital"},
    {0x000205, "Light & Sound Control Devices LLC"},
    {0x000206, "Retronyms Inc"},
    {0x000207, "JS Technologies"},
    {0x000208, "Quicco Sound"},
    {0x000209, "A-Designs Audio"},
    {0x00020A, "McCarthy Music Corp"},
    {0x00020B, "Denon DJ"},
    {0x00020C, "Keith Robert Murray"},
    {0x00020D, "Google"},
    {0x00020E, "ISP Technologies"},
    {0x00020F, "Abstrakt Instruments LLC"},
    {0x000210, "Meris LLC"},
    {0x000211, "Sensorpoint LLC"},
    {0x000212, "Hi-Z Labs"},
    {0x000213, "Imitone"},
    {0x000214, "Intellijel Designs Inc."},
    {0x000215, "Dasz Instruments Inc."},
    {0x000216, "Remidi"},
    {0x000217, "Disaster Area Designs LLC"},
    {0x000218, "Universal Audio"},
    {0x000219, "Carter Duncan Corp"},
    {0x00021A, "Essential Technology"},
    {0x00021B, "Cantux Research LLC"},
    {0x00021C, "Hummel Technologies"},
    {0x00021D, "Sensel Inc"},
    {0x00021E, "DBML Group"},
    {0x00021F, "Madrona Labs"},
    {0x000220, "Mesa Boogie"},
    {0x000221, "Effigy Labs"},
    {0x000222, "MK2 Image Ltd"},
    {0x000223, "Red Panda LLC"},
    {0x000224, "OnSong LLC"},
    {0x000225, "Jamboxx Inc."},
    {0x000226, "Electro-Harmonix "},
    {0x000227, "RnD64 Inc"},
    {0x000228, "Neunaber Technology LLC "},
    {0x000229, "Kaom Inc."},
    {0x00022A, "Hallowell EMC"},
    {0x00022B, "Sound Devices, LLC"},
    {0x00022C, "Spectrasonics, Inc"},
    {0x00022D, "Second Sound, LLC"},
    {0x002000, "Dream SAS"},
    {0x002001, "Strand Lighting"},
    {0x002002, "Amek Div of Harman Industries"},
    {0x002003, "Casa Di Risparmio Di Loreto"},
    {0x002004, "Böhm electronic GmbH"},
    {0x002005, "Syntec Digital Audio"},
    {0x002006, "Trident Audio Developments"},
    {0x002007, "Real World Studio"},
    {0x002008, "Evolution Synthesis, Ltd"},
    {0x002009, "Yes Technology"},
    {0x00200A, "Audiomatica"},
    {0x00200B, "Bontempi SpA (Sigma)"},
    {0x00200C, "F.B.T. Elettronica SpA"},
    {0x00200D, "MidiTemp GmbH"},
    {0x00200E, "LA Audio (Larking Audio)"},
    {0x00200F, "Zero 88 Lighting Limited"},
    {0x002010, "Micon Audio Electronics GmbH"},
    {0x002011, "Forefront Technology"},
    {0x002012, "Studio Audio and Video Ltd."},
    {0x002013, "Kenton Electronics"},
    {0x002014, "Celco/ Electrosonic"},
    {0x002015, "ADB"},
    {0x002016, "Marshall Products Limited"},
    {0x002017, "DDA"},
    {0x002018, "BSS Audio Ltd."},
    {0x002019, "MA Lighting Technology"},
    {0x00201A, "Fatar SRL c/o Music Industries"},
    {0x00201B, "QSC Audio Products Inc."},
    {0x00201C, "Artisan Clasic Organ Inc."},
    {0x00201D, "Orla Spa"},
    {0x00201E, "Pinnacle Audio (Klark Teknik PLC)"},
    {0x00201F, "TC Electronics"},
    {0x002020, "Doepfer Musikelektronik GmbH"},
    {0x002021, "Creative ATC / E-mu"},
    {0x002022, "Seyddo/Minami"},
    {0x002023, "LG Electronics (Goldstar)"},
    {0x002024, "Midisoft sas di M.Cima & C"},
    {0x002025, "Samick Musical Inst. Co. Ltd."},
    {0x002026, "Penny and Giles (Bowthorpe PLC)"},
    {0x002027, "Acorn Computer"},
    {0x002028, "LSC Electronics Pty. Ltd."},
    {0x002029, "Focusrite/Novation"},
    {0x00202A, "Samkyung Mechatronics"},
    {0x00202B, "Medeli Electronics Co."},
    {0x00202C, "Charlie Lab SRL"},
    {0x00202D, "Blue Chip Music Technology"},
    {0x00202E, "BEE OH Corp"},
    {0x00202F, "LG Semicon America"},
    {0x002030, "TESI"},
    {0x002031, "EMAGIC"},
    {0x002032, "Behringer GmbH"},
    {0x002033, "Access Music Electronics"},
    {0x002034, "Synoptic"},
    {0x002035, "Hanmesoft"},
    {0x002036, "Terratec Electronic GmbH"},
    {0x002037, "Proel SpA"},
    {0x002038, "IBK MIDI"},
    {0x002039, "IRCAM"},
    {0x00203A, "Propellerhead Software"},
    {0x00203B, "Red Sound Systems Ltd"},
    {0x00203C, "Elektron ESI AB"},
    {0x00203D, "Sintefex Audio"},
    {0x00203E, "MAM (Music and More)"},
    {0x00203F, "Amsaro GmbH"},
    {0x002040, "CDS Advanced Technology BV (Lanbox)"},
    {0x002041, "Mode Machines (Touched By Sound GmbH)"},
    {0x002042, "DSP Arts"},
    {0x002043, "Phil Rees Music Tech"},
    {0x002044, "Stamer Musikanlagen GmbH"},
    {0x002045, "Musical Muntaner S.A. dba Soundart"},
    {0x002046, "C-Mexx Software"},
    {0x002047, "Klavis Technologies"},
    {0x002048, "Noteheads AB"},
    {0x002049, "Algorithmix"},
    {0x00204A, "Skrydstrup R&D"},
    {0x00204B, "Professional Audio Company"},
    {0x00204C, "NewWave Labs (MadWaves)"},
    {0x00204D, "Vermona"},
    {0x00204E, "Nokia"},
    {0x00204F, "Wave Idea"},
    {0x002050, "Hartmann GmbH"},
    {0x002051, "Lion's Tracs"},
    {0x002052, "Analogue Systems"},
    {0x002053, "Focal-JMlab"},
    {0x002054, "Ringway Electronics (Chang-Zhou) Co Ltd"},
    {0x002055, "Faith Technologies (Digiplug)"},
    {0x002056, "Showworks"},
    {0x002057, "Manikin Electronic"},
    {0x002058, "1 Come Tech"},
    {0x002059, "Phonic Corp"},
    {0x00205A, "Dolby Australia (Lake)"},
    {0x00205B, "Silansys Technologies"},
    {0x00205C, "Winbond Electronics"},
    {0x00205D, "Cinetix Medien und Interface GmbH"},
    {0x00205E, "A&G Soluzioni Digitali"},
    {0x00205F, "Sequentix GmbH"},
    {0x002060, "Oram Pro Audio"},
    {0x002061, "Be4 Ltd"},
    {0x002062, "Infection Music"},
    {0x002063, "Central Music Co. (CME)"},
    {0x002064, "genoQs Machines GmbH"},
    {0x002065, "Medialon"},
    {0x002066, "Waves Audio Ltd"},
    {0x002067, "Jerash Labs"},
    {0x002068, "Da Fact"},
    {0x002069, "Elby Designs"},
    {0x00206A, "Spectral Audio"},
    {0x00206B, "Arturia"},
    {0x00206C, "Vixid"},
    {0x00206D, "C-Thru Music"},
    {0x00206E, "Ya Horng Electronic Co LTD"},
    {0x00206F, "SM Pro Audio"},
    {0x002070, "OTO Machines"},
    {0x002071, "ELZAB S.A. (G LAB)"},
    {0x002072, "Blackstar Amplification Ltd"},
    {0x002073, "M3i Technologies GmbH"},
    {0x002074, "Gemalto (from Xiring)"},
    {0x002075, "Prostage SL"},
    {0x002076, "Teenage Engineering"},
    {0x002077, "Tobias Erichsen Consulting"},
    {0x002078, "Nixer Ltd"},
    {0x002079, "Hanpin Electron Co Ltd"},
    {0x00207A, "\"MIDI-hardware\" R.Sowa"},
    {0x00207B, "Beyond Music Industrial Ltd"},
    {0x00207C, "Kiss Box B.V."},
    {0x00207D, "Misa Digital Technologies Ltd"},
    {0x00207E, "AI Musics Technology Inc"},
    {0x00207F, "Serato Inc LP"},
    {0x002100, "Limex"},
    {0x002101, "Kyodday (Tokai)"},
    {0x002102, "Mutable Instruments"},
    {0x002103, "PreSonus Software Ltd"},
    {0x002104, "Ingenico (was Xiring)"},
    {0x002105, "Fairlight Instruments Pty Ltd"},
    {0x002106, "Musicom Lab"},
    {0x002107, "Modal Electronics (Modulus/VacoLoco)"},
    {0x002108, "RWA (Hong Kong) Limited"},
    {0x002109, "Native Instruments"},
    {0x00210A, "Naonext"},
    {0x00210B, "MFB"},
    {0x00210C, "Teknel Research"},
    {0x00210D, "Ploytec GmbH"},
    {0x00210E, "Surfin Kangaroo Studio"},
    {0x00210F, "Philips Electronics HK Ltd"},
    {0x002110, "ROLI Ltd"},
    {0x002111, "Panda-Audio Ltd"},
    {0x002112, "BauM Software"},
    {0x002113, "Machinewerks Ltd."},
    {0x002114, "Xiamen Elane Electronics"},
    {0x002115, "Marshall Amplification PLC"},
    {0x002116, "Kiwitechnics Ltd"},
    {0x002117, "Rob Papen"},
    {0x002118, "Spicetone OU"},
    {0x002119, "V3Sound"},
    {0x00211A, "IK Multimedia"},
    {0x00211B, "Novalia Ltd"},
    {0x00211C, "Modor Music"},
    {0x00211D, "Ableton"},
    {0x00211E, "Dtronics"},
    {0x00211F, "ZAQ Audio"},
    {0x002120, "Muabaobao Education Technology Co Ltd"},
    {0x002121, "Flux Effects"},
    {0x002122, "Audiothingies (MCDA)"},
    {0x002123, "Retrokits"},
    {0x002124, "Morningstar FX Pte Ltd"},
    {0x002125, "Changsha Hotone Audio Co Ltd"},
    {0x002126, "Expressive E"},
    {0x002127, "Expert Sleepers Ltd"},
    {0x002128, "Timecode-Vision Technology"},
    {0x002129, "Hornberg Research GbR"},
    {0x00212A, "Sonic Potions"},
    {0x00212B, "Audiofront"},
    {0x00212C, "Fred's Lab"},
    {0x00212D, "Audio Modeling"},
    {0x00212E, "C. Bechstein Digital GmbH"},
    {0x00212F, "Motas Electronics Ltd"},
    {0x002130, "MIND Music Labs"},
    {0x002131, "Sonic Academy Ltd"},
    {0x002132, "Bome Software"},
    {0x002133, "AODYO SAS"},
    {0x002134, "Pianoforce S.R.O"},
    {0x002135, "Dreadbox P.C."},
    {0x002136, "TouchKeys Instruments Ltd"},
    {0x002137, "The Gigrig Ltd"},
    {0x002138, "ALM Co"},
    {0x002139, "CH Sound Design"},
    {0x00213A, "Beat Bars"},
    {0x00213B, "Blokas"},
    {0x00213C, "GEWA Music GmbH"},
    {0x00213D, "dadamachines"},
    {0x00213E, "Augmented Instruments Ltd (Bela)"},
    {0x00213F, "Supercritical Ltd"},
    {0x004000, "Crimson Technology Inc."},
    {0x004001, "Softbank Mobile Corp"},
    {0x004003, "D&M Holdings Inc."},
    {0,NULL}
};
static value_string_ext sysex_extended_manufacturer_id_vals_ext =
    VALUE_STRING_EXT_INIT(sysex_extended_manufacturer_id_vals);

/* dissector for System Exclusive MIDI data */
static int
dissect_sysex_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    guint8 sysex_helper;
    gint data_len;
    proto_item *item;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint offset = 0;
    gint manufacturer_payload_len;
    guint8 manufacturer_id;
    guint32 three_byte_manufacturer_id = 0xFFFFFF;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SYSEX");
    col_set_str(pinfo->cinfo, COL_INFO, "MIDI System Exclusive Command");

    data_len = tvb_reported_length(tvb);

    ti = proto_tree_add_protocol_format(parent_tree, proto_sysex, tvb, 0, -1, "MIDI System Exclusive Command");
    tree = proto_item_add_subtree(ti, ett_sysex);

    /* Check start byte (System Exclusive - 0xF0) */
    sysex_helper = tvb_get_guint8(tvb, 0);
    item = proto_tree_add_item(tree, hf_sysex_message_start, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (sysex_helper != 0xF0)
    {
        expert_add_info(pinfo, item, &ei_sysex_message_start_byte);
    }

    offset++;

    manufacturer_id = tvb_get_guint8(tvb, offset);
    /* Three-byte manufacturer ID starts with 00 */
    if (manufacturer_id == 0)
    {
        three_byte_manufacturer_id = tvb_get_ntoh24(tvb, offset);
        proto_tree_add_item(tree, hf_sysex_three_byte_manufacturer_id, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
    }
    /* One-byte manufacturer ID */
    else
    {
        proto_tree_add_item(tree, hf_sysex_manufacturer_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    /* Following data is menufacturer-specific */
    manufacturer_payload_len = data_len - offset - 1;
    if (manufacturer_payload_len > 0)
    {
        tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, offset, manufacturer_payload_len);
        switch (three_byte_manufacturer_id)
        {
            case SYSEX_MANUFACTURER_DOD:
            {
                offset += call_dissector(sysex_digitech_handle, payload_tvb, pinfo, parent_tree);
                break;
            }
            default:
                break;
        }
    }

    if (offset < data_len - 1)
    {
        proto_tree_add_expert(tree, pinfo, &ei_sysex_undecoded, tvb, offset, data_len - offset - 1);
    }

    /* Check end byte (EOX - 0xF7) */
    sysex_helper = tvb_get_guint8(tvb, data_len - 1);
    item = proto_tree_add_item(tree, hf_sysex_message_eox, tvb, data_len - 1, 1, ENC_BIG_ENDIAN);
    if (sysex_helper != 0xF7)
    {
        expert_add_info(pinfo, item, &ei_sysex_message_end_byte);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_sysex(void)
{
    static hf_register_info hf[] = {
        { &hf_sysex_message_start,
            { "SysEx message start", "sysex.start", FT_UINT8, BASE_HEX,
              NULL, 0, "System Exclusive Message start (0xF0)", HFILL }},
        { &hf_sysex_manufacturer_id,
            { "Manufacturer ID", "sysex.manufacturer_id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &sysex_manufacturer_id_vals_ext, 0, NULL, HFILL }},
        { &hf_sysex_three_byte_manufacturer_id,
            { "Manufacturer ID", "sysex.manufacturer_id", FT_UINT24, BASE_HEX|BASE_EXT_STRING,
              &sysex_extended_manufacturer_id_vals_ext, 0, NULL, HFILL }},
        { &hf_sysex_message_eox,
            { "EOX", "sysex.eox", FT_UINT8, BASE_HEX,
              NULL, 0, "System Exclusive Message end (0xF7)", HFILL}},
    };

    static gint *sysex_subtrees[] = {
        &ett_sysex
    };

    static ei_register_info ei[] = {
        { &ei_sysex_message_start_byte, { "sysex.message_start_byte", PI_PROTOCOL, PI_WARN, "SYSEX Error: Wrong start byte", EXPFILL }},
        { &ei_sysex_message_end_byte, { "sysex.message_end_byte", PI_PROTOCOL, PI_WARN, "SYSEX Error: Wrong end byte", EXPFILL }},
        { &ei_sysex_undecoded, { "sysex.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    expert_module_t* expert_sysex;

    proto_sysex = proto_register_protocol("MIDI System Exclusive", "SYSEX", "sysex");
    proto_register_field_array(proto_sysex, hf, array_length(hf));
    proto_register_subtree_array(sysex_subtrees, array_length(sysex_subtrees));
    expert_sysex = expert_register_protocol(proto_sysex);
    expert_register_field_array(expert_sysex, ei, array_length(ei));

    register_dissector("sysex", dissect_sysex_command, proto_sysex);
}

void
proto_reg_handoff_sysex(void)
{
    sysex_digitech_handle = find_dissector_add_dependency("sysex_digitech", proto_sysex);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
