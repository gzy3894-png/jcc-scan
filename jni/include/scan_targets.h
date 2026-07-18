#ifndef JCC_SCAN_TARGETS_H
#define JCC_SCAN_TARGETS_H

/* 定向扫描目标 —— 与 JCC Controller / dump 分析对齐 */

typedef struct {
    const char *ns;   /* 可空串 */
    const char *name;
} jcc_class_target_t;

static const jcc_class_target_t k_classes[] = {
    {"ZGameClient", "TACG_Hero_Client"},
    {"ZGame", "DataBaseManager"},
    {"", "BuyHeroView"},
    {"", "ChessBattleStage"},
    {"", "ChessBattleModel"},
    {"", "ChessBattleLogicPlayer"},
    {"", "PlayerModel"},
    {"", "ChessPlayerController"},
    {"", "ChessPlayerUnit"},
    {"", "ChessBattleUnit"},
    {"", "UnitData"},
    {"", "PlayerListPanel"},
    {"", "PlayerListItem"},
    {"", "PlayerHeadInfo"},
    {"", "RoundSelectPlayerUnit"},
    {"", "TinyHero"},
    {"", "WarehouseModel"},
    {"", "AssetBundleManager"},
    {"", "BattleMapManager"},
    {"", "ACGEventManager"},
    {0, 0},
};

static const char *k_methods[] = {
    "SearchACGHero",
    "SearchACGHero2",
    "SearchACGHeroAndStar",
    "SearchTinyHero",
    "OnRefreshHeroRet",
    "OnBuyHeroRet",
    "HandleRefreshBuyHero",
    "HandleBuyHero",
    "ReqBuyHero",
    "ReqRefresh",
    "GetMyPlayerModel",
    "get_MyPlayerId",
    "GetMatchPlayerId",
    "GetPlayer",
    "GetBattleModel",
    "GetHeroHeadIconAB",
    "get_Instance",
    "UpdateBattleMap",
    "UpdateNameAndMoney",
    0,
};

#endif
