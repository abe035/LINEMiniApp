<?php
header("Content-Type: application/json; charset=utf-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET,POST");
header("Access-Control-Allow-Headers: Content-Type");

// 秘密ファイルへのアクセスを許可するフラグ
define('ALLOW_ACCESS', true);

// 【変更点】同じ階層（./）のファイルを読み込む
require_once __DIR__ . '/secure_config.php';

$host = defined('HOSTNAME') ? HOSTNAME : false;
$dbname = defined('DBNAME') ? DBNAME : false;
$user = defined('DBUSER') ? DBUSER : false;
$pass = defined('DBPASS') ? DBPASS : false;
$VALID_KEY = defined('VALID_KEY') ? VALID_KEY : false;


if (!isset($_POST["db_ApiKey"]) ) {
    echo json_encode(["error" => "api key is not set"]);
    exit;
}

//Lineからのみアクセス可とする。（本番用）
//if (strpos($_SERVER['HTTP_USER_AGENT'], 'Line') === false) {
//    exit(json_encode(["error" => "forbidden"]));
//}

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    echo json_encode(["error" => $e->getMessage()]);
    exit;
}

require_once 'db_log_util.php';
$configPath = __DIR__ . '/db_logconfig.php';

$logger = new LogUtil($configPath, $pdo);

$db_token = $_POST["db_token"] ?? "";

$del = time() - 600;

$pdo->prepare("DELETE FROM api_token WHERE created_at < :del")
    ->execute([":del" => $del]);

$stmt = $pdo->prepare("SELECT expire_at FROM api_token WHERE token = :token");
$stmt->execute([":token" => $db_token]);
$row = $stmt->fetch();

if (!$row || time() > $row["expire_at"]) {
    echo json_encode(["error" => "invalid or expired token"]);
    exit;
}

$stmt = $pdo->prepare("SELECT * FROM api_token WHERE token = :token");
$stmt->execute([':token' => $db_token]);
$row = $stmt->fetch();

if (!$row) {
    // token 不一致 → エラー
    echo json_encode(["error" => "invalid token"]);
    exit;
}

// token が一致したので削除（ワンタイム）
$pdo->prepare("DELETE FROM api_token WHERE token = :token")
    ->execute([':token' => $db_token]);



// POST データ取得
$action = $_POST["action"] ?? "";
// 現在の時刻取得
$now = date("Y-m-d H:i:s");

switch ($action) {

    //-------------------------
    // ユーザー情報の取得
    //-------------------------
    case "getUserData":
        $stmt = $pdo->prepare("
            SELECT *,
            EMPLOY.COMP_ID AS EM_COMP_ID,
            SISETU.COMP_ID AS SI_COMP_ID
            FROM EMPLOY_TBL EMPLOY
            INNER JOIN SISETU_TBL SISETU
            ON EMPLOY.COMP_ID = SISETU.COMP_ID
            WHERE EMPLOY.LINE_ID = :LineID
        ");

        $stmt->execute([
	        ":LineID" => $_POST["LineID"]
	    ]);
        
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
        break;

    // -------------------------
    // ユーザ情報の登録
    // -------------------------
    case "registerUser":
        $stmt = $pdo->prepare("
            INSERT INTO EMPLOY_TBL (
                COMP_ID,
                LINE_ID,
                EMPLOY_PASSWORD,
                PHONE,
                MAIL,
                NAME
            ) VALUES (
                :COMP_ID,
                :LINE_ID,
                :EMPLOY_PASSWORD,
                :PHONE,
                :MAIL,
                :NAME
            )
        ");
        $stmt->execute([
            ":COMP_ID" => $_POST["CompID"] ?? "",
            ":LINE_ID" => $_POST["LineID"] ?? "",
            ":EMPLOY_PASSWORD" => $_POST["Password"] ?? "",
            ":PHONE" => $_POST["Tel"] ?? "",
            ":MAIL" => $_POST["Email"] ?? "",            
            ":NAME" => $_POST["Name"] ?? ""
        ]);

        echo json_encode(["status" => "registerUser"]);
        break;

    // -------------------------
    // 募集情報の登録
    // -------------------------
    case "Bosyuu":
        $stmt = $pdo->query("SELECT COALESCE(MAX(REQ_ID), 0) + 1 AS next_id FROM REQ_TBL");
        $nextId = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            INSERT INTO `REQ_TBL` (
                `REQ_ID`,
                `COMP_ID`,
                `COMP_NAME`,
                `NAME`,
                `START`,
                `USER_NAME`,
                `AGE`,
                `SEX`,
                `CARE_LEVEL`,
                `REMARK`,
                `COMMENT`,
                `CREATE_AT`,
                `CREATE_BY`,
                `UPDATE_AT`,
                `UPDATE_BY`
            ) VALUES (
                :REQ_ID,
                :COMP_ID,
                :COMP_NAME,
                :NAME,
                :START,
                :USER_NAME,
                :AGE,
                :SEX,
                :CARE_LEVEL,
                :REMARK,
                :COMMENT,
                :CREATE_AT,
                :CREATE_BY,
                :UPDATE_AT,
                :UPDATE_BY
            )
        ");
        $stmt->execute([
            ":REQ_ID" => $nextId,
            ":COMP_ID" => $_POST["recruitmentCompId"] ?? '',
            ":COMP_NAME" => $_POST["recruitmentCompName"] ?? '',
            ":NAME" => $_POST["recruitmentManagerName"] ?? '',
            ":START" => $_POST["recruitmentStartDateTime"] ?? null,
            ":USER_NAME" => $_POST["recruitmentName"] ?? '',
            ":AGE" => $_POST["recruitmentAge"] ?? 0,
            ":SEX" => $_POST["recruitmentGender"] ?? '',
            ":CARE_LEVEL" => $_POST["recruitmentCareLevel"] ?? 0,
            ":REMARK" => $_POST["recruitmentFreeText"] ?? '',
            ":COMMENT" => $_POST["recruitmentResultOutput"] ?? '',
            ":CREATE_AT" => $now,
            ":CREATE_BY" => $_POST["LineID"] ?? '',
            ":UPDATE_AT" => $now,
            ":UPDATE_BY" => $_POST["LineID"] ?? ''
        ]);
        echo json_encode([
            "status" => "Bosyuu",
            "REQ_ID" => $nextId
        ]);
        break;

    //-------------------------
    // 募集情報の取得(募集情報一覧表示)
    //-------------------------
    case "BosyuuIchiranHyouzi":
        if (($_POST["includeEnded"] ?? "0") === "1") {
            $stmt = $pdo->query("SELECT * FROM REQ_TBL");
        } else {
            $stmt = $pdo->query("SELECT * FROM REQ_TBL WHERE FLAG = 0 AND DELETE_FLAG = 0");
        }
        
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
        break;

    //-------------------------
    // 応募者本人の応募履歴を募集情報として取得
    //-------------------------
    case "MyOuboRecruitmentList":
        $stmt = $pdo->prepare("
            SELECT REQ.*, APPLICATION.RES_ID, APPLICATION.CREATE_BY AS OUBOSYA_LINE_ID
            FROM REQ_TBL REQ
            INNER JOIN (
                SELECT REQ_ID, MIN(RES_ID) AS RES_ID, CREATE_BY
                FROM RES_TBL
                WHERE CREATE_BY = :LineID AND DELETE_FLAG = 0
                GROUP BY REQ_ID, CREATE_BY
            ) APPLICATION ON APPLICATION.REQ_ID = REQ.REQ_ID
        ");
        $stmt->execute([
            ":LineID" => $_POST["LineID"]
        ]);

        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
        break;

    //-------------------------
    // 募集情報の取得(LINEの応募リンククリック時)
    //-------------------------
    case "BosyuuSyousaiHyouzi":
        $stmt = $pdo->prepare("
            SELECT * 
            FROM REQ_TBL 
            WHERE FLAG = 0 AND DELETE_FLAG = 0 AND REQ_ID = :REQ_ID
        ");
        $stmt->execute([
            ":REQ_ID" => $_POST["recruitmentID"]
        ]);
        
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
        break;

    //-------------------------
    // 応募情報の登録
    //-------------------------
    case "Oubo":
        // 応募ID割り振りのための処理
        $stmt = $pdo->query("SELECT COALESCE(MAX(RES_ID), 0) + 1 AS next_id FROM RES_TBL");
        $nextId = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            INSERT INTO `RES_TBL` (
                `RES_ID`,
                `REQ_ID`,
                `COMP_ID`,
                `NAME`,
                `CREATE_AT`,
                `CREATE_BY`,
                `UPDATE_AT`,
                `UPDATE_BY`
            )VALUES (
                :RES_ID,
                :REQ_ID,
                :COMP_ID,
                :NAME,
                :CREATE_AT,
                :CREATE_BY,
                :UPDATE_AT,
                :UPDATE_BY
            )
        ");
        $stmt->execute([
            ":RES_ID" => $nextId,
            ":REQ_ID" => $_POST["recruitmentID"],
            ":COMP_ID" => $_POST["applyOfficeNumber"],
            ":NAME" => $_POST['ManagerName'],
            ":CREATE_AT" => $now,
            ":CREATE_BY" => $_POST["LineID"],
            ":UPDATE_AT" => $now,
            ":UPDATE_BY" => $_POST["LineID"]
        ]);
        echo json_encode([
            "status" => "Oubo",
            "RES_ID" => $nextId
        ]);
        break;

    //-------------------------
    // 応募情報の取得(応募情報一覧表示)
    //-------------------------
    case "OuboIchiranHyouzi":
        $stmt = $pdo->prepare("
            SELECT *, 
			REQ.REQ_ID AS REQ_REQ_ID,
            RES.REQ_ID AS RES_REQ_ID, 
            RES.CREATE_BY AS OUBOSYA_LINE_ID, 
            REQ.CREATE_BY AS BOSYUUSYA_LINE_ID,
            REQ.COMP_ID AS REQ_COMP_ID,
            SISETU.COMP_ID AS SISETU_COMP_ID,
            REQ.COMP_NAME AS REQ_COMP_NAME,
            SISETU.COMP_NAME AS SISETU_COMP_NAME,
            REQ.NAME AS REQ_NAME,
            RES.NAME AS RES_NAME,
            REQ.DELETE_FLAG AS REQ_DELETE_FLAG,
            RES.DELETE_FLAG AS RES_DELETE_FLAG
            FROM RES_TBL RES 
            INNER JOIN REQ_TBL REQ 
                ON RES.REQ_ID = REQ.REQ_ID 
            INNER JOIN SISETU_TBL SISETU 
                ON RES.COMP_ID = SISETU.COMP_ID 
            WHERE RES.MATCHING = 0 AND REQ.FLAG = 0 AND RES.DELETE_FLAG = 0 AND REQ.CREATE_BY = :LineID
        ");
        $stmt->execute([
            ":LineID" => $_POST["LineID"]
	    ]);

        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
        break;

    //-------------------------
    // 応募情報の取得(LINEの応募リンククリック時)
    //-------------------------
    case "OuboSyousaiHyouzi":
        $stmt = $pdo->prepare("
            SELECT *, 
            RES.CREATE_BY AS OUBOSYA_LINE_ID, 
            REQ.CREATE_BY AS BOSYUUSYA_LINE_ID,
            REQ.COMP_ID AS REQ_COMP_ID,
            SISETU.COMP_ID AS SISETU_COMP_ID,
            REQ.COMP_NAME AS REQ_COMP_NAME,
            SISETU.COMP_NAME AS SISETU_COMP_NAME,
            REQ.NAME AS REQ_NAME,
            RES.NAME AS RES_NAME,
            REQ.DELETE_FLAG AS REQ_DELETE_FLAG,
            RES.DELETE_FLAG AS RES_DELETE_FLAG
            FROM RES_TBL RES 
            INNER JOIN REQ_TBL REQ 
                ON RES.REQ_ID = REQ.REQ_ID 
            INNER JOIN SISETU_TBL SISETU 
                ON RES.COMP_ID = SISETU.COMP_ID 
            WHERE RES.MATCHING = 0 AND REQ.FLAG = 0 AND RES.DELETE_FLAG = 0 AND RES_ID = :RES_ID
        ");
        $stmt->execute([
            ":RES_ID" => $_POST["ApprovalID"]
        ]);
        
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
        break;

    // -------------------------
    // 承認時、募集・応募テーブルのフラグ更新
    // -------------------------
	case "changeFlag":
        // 募集テーブルのフラグ更新
	    $stmt = $pdo->prepare("
	        UPDATE REQ_TBL SET 
            FLAG = 1,
            UPDATE_AT = :UPDATE_AT,
            UPDATE_BY = :UPDATE_BY
	        WHERE REQ_ID = :REQ_ID
	    ");
	    $stmt->execute([
            ":UPDATE_AT" => $now,
            ":UPDATE_BY" => $_POST["LineID"],
	        ":REQ_ID" => $_POST["recruitmentID"]
	    ]);

        // 応募テーブルのフラグ更新
        $stmt = $pdo->prepare(" 
	        UPDATE RES_TBL SET
            MATCHING = 1,
            UPDATE_AT = :UPDATE_AT,
            UPDATE_BY = :UPDATE_BY
	        WHERE REQ_ID = :REQ_ID
	    ");
	    $stmt->execute([
            ":UPDATE_AT" => $now,
            ":UPDATE_BY" => $_POST["LineID"],
	        ":REQ_ID" => $_POST["recruitmentID"]
	    ]);
	    echo json_encode(["status" => "changeFlag"]);
	    break;

    // -------------------------
    // 募集・応募キャンセル
    // -------------------------
    case "REQ_CANCEL":
        // 募集テーブル
        $stmt = $pdo->prepare("
	        UPDATE REQ_TBL 
            SET DELETE_FLAG = 1,
            UPDATE_AT = :UPDATE_AT,
            UPDATE_BY = :UPDATE_BY
	        WHERE REQ_ID = :REQ_ID
	    ");
	    $stmt->execute([
            ":UPDATE_AT" => $now,
            ":UPDATE_BY" => $_POST["LineID"],
	        ":REQ_ID" => $_POST["recruitmentID"]
	    ]);

        echo json_encode(["status" => "REQ_CANCEL"]);
	    break;

    case "RES_CANCEL":
        // 応募テーブル
        $stmt = $pdo->prepare("
	        UPDATE RES_TBL 
            SET DELETE_FLAG = 1,
            UPDATE_AT = :UPDATE_AT,
            UPDATE_BY = :UPDATE_BY
            WHERE RES_ID = :RES_ID
            AND CREATE_BY = :LINE_ID
            AND DELETE_FLAG = 0
	    ");
	    $stmt->execute([
            ":UPDATE_AT" => $now,
            ":UPDATE_BY" => $_POST["LineID"],
	        ":RES_ID" => $_POST["OubosyaID"],
            ":LINE_ID" => $_POST["LineID"]
	    ]);

	    echo json_encode($stmt->rowCount() > 0
            ? ["status" => "RES_CANCEL"]
            : ["error" => "application not found"]);
	    break;

}
