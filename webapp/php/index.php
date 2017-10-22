<?php

require 'vendor/autoload.php';

use Slim\Http\Request;
use Slim\Http\Response;

use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\FigRequestCookies;
use Dflydev\FigCookies\Cookie;
use Dflydev\FigCookies\SetCookie;

date_default_timezone_set('Asia/Tokyo');

define("TWIG_TEMPLATE_FOLDER", realpath(__DIR__) . "/views");
define("AVATAR_MAX_SIZE", 1 * 1024 * 1024);

function getPDO()
{
    static $pdo = null;
    if (!is_null($pdo)) {
        return $pdo;
    }

    $host = getenv('ISUBATA_DB_HOST') ?: 'localhost';
    $port = getenv('ISUBATA_DB_PORT') ?: '3306';
    $user = getenv('ISUBATA_DB_USER') ?: 'root';
    $password = getenv('ISUBATA_DB_PASSWORD') ?: '';
    $dsn = "mysql:host={$host};port={$port};dbname=isubata;charset=utf8mb4";

    $pdo = new PDO(
        $dsn,
        $user,
        $password,
        [
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]
    );
    $pdo->query("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'");
    return $pdo;
}

function getRedisCli()
{
  static $cli = null;
  if (!is_null($cli)) {
      return $cli;
  }
  $cli = new Predis\Client([
    'scheme' => 'tcp',
    'host'   => '192.168.101.3',
    'port'   => 6379,
  ]);
  return $cli;
}

function makeMessage($redis, $channelId, $timestamp, $userId, $content)
{
    $key = 'message:'. $channelId;
    $score = ($redis->zcard($key)) ?? 0;
    $redis->zadd(
        $key,
        $score+1,
        json_encode((['user' => $userId, 'content' => $content, 'timestamp' => $timestamp])));
}

$app = new \Slim\App();

$container = $app->getContainer();

$container['view'] = function ($container) {
    $view = new \Slim\Views\Twig(TWIG_TEMPLATE_FOLDER, []);
    $view->addExtension(
        new \Slim\Views\TwigExtension(
            $container['router'],
            $container['request']->getUri()
        )
    );
    return $view;
};

$app->get('/initialize', function (Request $request, Response $response) {

    $redis = getRedisCli();
    // messageテーブルのredisデータの破棄
    $redis->flushdb();

    // image del
    // $redis = getRedisCli();
    // $stmt = $dbh->prepare("SELECT name FROM image WHERE id > 1001");
    // $stmt->execute();
    // $images= $stmt->fetchall();
    // foreach ($images as $image) {
    //   $redis->del("img_". $image['name']);
    //   $redis->del("img_time_". $image['name']);
    // }

    $dbh = getPDO();
    $dbh->query("DELETE FROM user WHERE id > 1000");
    $dbh->query("DELETE FROM image WHERE id > 1001");
    $dbh->query("DELETE FROM channel WHERE id > 10");
    $dbh->query("DELETE FROM message WHERE id > 10000");
    $dbh->query("DELETE FROM haveread");



    // messageテーブルのredis化
    // 追加、第２引数がscoreで、取得時はこの値でソートされた結果が返ってくる
    $stmt = $dbh->prepare("SELECT channel_id, user_id, content, created_at FROM message");
    $stmt->execute();
    while ($row = $stmt->fetch()) {
        makeMessage(
            $redis,
            $row['channel_id'],
            strtotime($row['created_at']),
            $row['user_id'],
            $row['content']
        );
    }

    // image
    // $redis = getRedisCli();
    // $stmt = $dbh->prepare("SELECT name, data FROM image");
    // $stmt->execute();
    // while ($row = $stmt->fetch()) {
    //   $redis->set("img_". $row['name'], $row['data']);
    //   $redis->set("img_time_". $row['name'], time());
    // }

    $stmt = $dbh->prepare("SELECT id, name, salt, password FROM user");
    $stmt->execute();
    while ($row = $stmt->fetch()) {
      $redis->set("user_id_". $row['name'], $row['id']);
      $redis->set("user_pass_". $row['name'], $row['password']);
      $redis->set("user_salt_". $row['name'], $row['salt']);
    }
    $response->withStatus(204);
});

function db_get_user($dbh, $userId)
{
    $stmt = $dbh->prepare("SELECT * FROM user WHERE id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetch();
}

function db_add_message($dbh, $channelId, $userId, $message)
{
    // $stmt = $dbh->prepare("INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
    // $stmt->execute([$channelId, $userId, $message]);
    $redis = getRedisCli();
    makeMessage(
        $redis,
        $channelId,
        time(),
        $userId,
        $message
    );
}

$loginRequired = function (Request $request, Response $response, $next) use ($container) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withRedirect('/login', 303);
    }

    $request = $request->withAttribute('user_id', $userId);
    $container['view']->offsetSet('user_id', $userId);

    $user = db_get_user(getPDO(), $userId);
    if (!$user) {
        $response = FigResponseCookies::remove($response, 'user_id');
        return $response->withRedirect('/login', 303);
    }

    $request = $request->withAttribute('user', $user);
    $container['view']->offsetSet('user', $user);

    $response = $next($request, $response);
    return $response;
};

function random_string($length)
{
    $str = "";
    while ($length--) {
        $str .= str_shuffle("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")[0];
    }
    return $str;
}

function register($dbh, $userName, $password)
{
    $salt = random_string(20);
    $passDigest = sha1(utf8_encode($salt . $password));
    //
    // $redis = getRedisCli();
    // $redis->set("user_pass_". $userName, $passDigest);
    // $redis->set("user_salt_". $userName, $salt);

    $stmt = $dbh->prepare(
        "INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at) ".
        "VALUES (?, ?, ?, ?, 'default.png', NOW())"
    );
    $stmt->execute([$userName, $salt, $passDigest, $userName]);
    $stmt = $dbh->query("SELECT LAST_INSERT_ID() AS last_insert_id");
    //
    // $userId = $stmt->fetch()['last_insert_id'];
    // $redis->set("user_id_". $userName, $userId);
    // return $userId;
    return $stmt->fetch()['last_insert_id'];
}

$app->get('/', function (Request $request, Response $response) {
    if (FigRequestCookies::get($request, 'user_id')->getValue()) {
        return $response->withRedirect('/channel/1', 303);
    }
    return $this->view->render($response, 'index.twig', []);
});

function get_channel_list_info($focusedChannelId = null)
{
    if ($focusedChannelId === null)
    {
        $columns = 'id, name';
    }
    else
    {
        $columns = 'id, name, description';
    }
    $stmt = getPDO()->query('SELECT '.$columns.' FROM channel ORDER BY id');
    $channels = $stmt->fetchall();
    $description = "";

    if ($focusedChannelId !== null)
    {
        foreach ($channels as $channel) {
            if ((int)$channel['id'] === (int)$focusedChannelId) {
                $description = $channel['description'];
                break;
            }
        }
    }
    return [$channels, $description];
}

$app->get('/channel/{channel_id}', function (Request $request, Response $response) {
    $channelId = $request->getAttribute('channel_id');
    list($channels, $description) = get_channel_list_info($channelId);
    return $this->view->render(
        $response,
        'channel.twig',
        [
            'channels' => $channels,
            'channel_id' => $channelId,
            'description' => $description
        ]
    );
})->add($loginRequired);

$app->get('/register', function (Request $request, Response $response) {
    return $this->view->render($response, 'register.twig', []);
});

$app->post('/register', function (Request $request, Response $response) {
    $name     = $request->getParam('name');
    $password = $request->getParam('password');

    if (!$name || !$password) {
        return $response->withStatus(400);
    }
    try {
        $userId = register(getPDO(), $name, $password);
    } catch (PDOException $e) {
        if ($e->errorInfo[1] === 1062) {
            return $response->withStatus(409);
        }
        throw $e;
    }
    $response = FigResponseCookies::set($response, SetCookie::create('user_id', $userId));
    return $response->withRedirect('/', 303);
});

$app->get('/login', function (Request $request, Response $response) {
    return $this->view->render($response, 'login.twig', []);
});

$app->post('/login', function (Request $request, Response $response) {
    $name = $request->getParam('name');
    $password = $request->getParam('password');

    // $redis = getRedisCli();
    // $user_pass = $redis->get("user_pass_". $name);
    // $user_salt = $redis->get("user_salt_". $name);

    $stmt = getPDO()->prepare("SELECT * FROM user WHERE name = ?");
    $stmt->execute([$name]);
    $user = $stmt->fetch();
    if (!$user || $user['password'] !== sha1(utf8_encode($user['salt'] . $password))) {
    // if ($user_pass !== sha1(utf8_encode($user_salt . $password))) {
        return $response->withStatus(403);
    }
    $response = FigResponseCookies::set($response, SetCookie::create('user_id', $user['id']));
    // $response = FigResponseCookies::set($response, SetCookie::create('user_id', $redis->get("user_id_". $name)));
    return $response->withRedirect('/', 303);
});

$app->get('/logout', function (Request $request, Response $response) {
    $response = FigResponseCookies::set($response, SetCookie::create('user_id', '0'));
    return $response->withRedirect('/', 303);
});

$app->post('/message', function (Request $request, Response $response) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    $user = db_get_user(getPDO(), $userId);
    $message = $request->getParam('message');
    $channelId = (int)$request->getParam('channel_id');
    if (!$user || !$channelId || !$message) {
        return $response->withStatus(403);
    }
    db_add_message(getPDO(), $channelId, $userId, $message);
    return $response->withStatus(204);
});

$app->get('/message', function (Request $request, Response $response) {
    $dbh = getPDO();
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withStatus(403);
    }

    $channelId = $request->getParam('channel_id');
    $lastMessageId = $request->getParam('last_message_id');


    $res = [];
    $redis = getRedisCli();
    $key = "message:".$channelId;
    $result = $redis->zrange($key, 0, 99, ['withscores' => true]);
    $maxMessageId = 0;
    foreach($result as $val => $score)
    {
        if($score <= $lastMessageId)
        {
            break;
        }
        $row['id'] = $score;
        $data = json_decode($val, true);

        $r = [];
        $r['id'] = (int)$score;
        $stmt = $dbh->prepare("SELECT name, display_name, avatar_icon FROM user WHERE id = ?");
        $stmt->execute([$data['user']]);
        $r['user'] = $stmt->fetch();
        // $r['date'] = str_replace('-', '/', $data[2]);
        $r['date'] = date('Y/m/d H:i:s', $data['timestamp']);
        $r['content'] = $data['content'];
        $res[] = $r;
        $maxMessageId = (int)$score;
    }

    /**
    $dbh = getPDO();
    $stmt = $dbh->prepare(
        "SELECT id, user_id, content, created_at ".
        "FROM message ".
        "WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100"
    );
    $stmt->execute([$lastMessageId, $channelId]);
    $rows = $stmt->fetchall();
    $res = [];
    $maxMessageId = 0;
    foreach ($rows as $row) {
        $r = [];
        $r['id'] = (int)$row['id'];
        $stmt = $dbh->prepare("SELECT name, display_name, avatar_icon FROM user WHERE id = ?");
        $stmt->execute([$row['user_id']]);
        $r['user'] = $stmt->fetch();
        $r['date'] = str_replace('-', '/', $row['created_at']);
        $r['content'] = $row['content'];
        $res[] = $r;
        $maxMessageId = max($maxMessageId, $row['id']);
    }
     */
    $res = array_reverse($res);

    $dbh = getPDO();
    $stmt = $dbh->prepare(
        "INSERT INTO haveread (user_id, channel_id, message_id, updated_at, created_at) ".
        "VALUES (?, ?, ?, NOW(), NOW()) ".
        "ON DUPLICATE KEY UPDATE message_id = ?, updated_at = NOW()"
    );
    $stmt->execute([$userId, $channelId, $maxMessageId, $maxMessageId]);
    return $response->withJson($res);
});

$app->get('/fetch', function (Request $request, Response $response) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withStatus(403);
    }

    // sleep(1);

    $dbh = getPDO();
    $stmt = $dbh->query('SELECT id FROM channel');
    $rows = $stmt->fetchall();
    $channelIds = [];
    $haveread_rows = [];
    if (!empty($rows))
    {
        foreach ($rows as $row) {
            $channelIds[] = (int)$row['id'];
        }
        $stmt = $dbh->prepare('SELECT channel_id, message_id FROM haveread WHERE user_id = ? AND channel_id IN ('.implode(',', $channelIds).')');
        $stmt->execute([$userId]);
        $haveread_rows = $stmt->fetchall();
    }
    $havereads = [];
    foreach ($haveread_rows as $haveread_row) {
        $havereads[$haveread_row['channel_id']] = $haveread_row;
    }

    $redis = getRedisCli();

    $res = [];
    foreach ($channelIds as $channelId) {
        if (isset($havereads[$channelId])) {
            $row = $havereads[$channelId];
            $lastMessageId = $row['message_id'];
            // $stmt = $dbh->prepare(
            //     "SELECT COUNT(*) as cnt ".
            //     "FROM message ".
            //     "WHERE channel_id = ? AND ? < id"
            // );
            // $stmt->execute([$channelId, $lastMessageId]);

            // 要素数を取得、第2、第3引数で指定された範囲のscoreを持つ要素の数が返ってくる(valueは返ってこない)
            $key = "message:".$channelId;
            $cnt = $redis->zcount($key, 0, $lastMessageId);
        } else {
            $key = "message:".$channelId;
            $cnt = $redis->zcard($key);
        }
        $r = [];
        $r['channel_id'] = $channelId;
        //$r['unread'] = (int)$stmt->fetch()['cnt'];
        $r['unread'] = $cnt;
        $res[] = $r;
    }

    return $response->withJson($res);
});

$app->get('/history/{channel_id}', function (Request $request, Response $response) {
    $page = $request->getParam('page') ?? '1';
    $channelId = $request->getAttribute('channel_id');
    if (!is_numeric($page)) {
        return $response->withStatus(400);
    }
    $page = (int)$page;


    $dbh = getPDO();
    // $stmt = $dbh->prepare("SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?");
    // $stmt->execute([$channelId]);
    // $cnt = (int)($stmt->fetch()['cnt']);
    $redis = getRedisCli();
    $key = "message:".$channelId;

    $cnt = $redis->zcard($key);
    $pageSize = 20;
    $maxPage = ceil($cnt / $pageSize);
    if ($maxPage == 0) {
        $maxPage = 1;
    }

    if ($page < 1 || $maxPage < $page) {
        return $response->withStatus(400);
    }

    // $offset = ($page - 1) * $pageSize;
    // $stmt = $dbh->prepare(
    //     "SELECT * ".
    //     "FROM message ".
    //     "WHERE channel_id = ? ORDER BY id DESC LIMIT $pageSize OFFSET $offset"
    // );
    // $stmt->execute([$channelId]);
    // $rows = $stmt->fetchall();

    $page = $page < 1 ? 1: $page;
    // $result = $redis->zrange($key, ($page*20)-20, ($page*20)-1, ['withscores' => true]);
    // $result = $redis->zrevrange($key, ($page*20)-20, ($page*20)-1, ['withscores' => true]);
    $result = $redis->zrevrange($key, ($page*20)-20, ($page*20)-1, ['withscores' => true]);

    $user_ids = [];
    $users = [];
    foreach ($result as $val => $score) {
        $data = json_decode($val, true);
        $user_ids[] = $data['user'];
    }

    if (!empty($user_ids))
    {
        $stmt = $dbh->prepare('SELECT id, name, display_name, avatar_icon FROM user WHERE id IN ('.implode(',', $user_ids).')');
        $stmt->execute([]);
        $user_rows = $stmt->fetchall();
        foreach ($user_rows as $urows) {
            $users[$urows['id']] = $urows;
        }
    }

    $messages = [];
    foreach ($result as $val => $score) {

        $row['id'] = $score;
        $data = json_decode($val, true);
        $row['user_id'] = $data['user'];
        $row['content'] = $data['content'];
        $row['created_at'] = $data['timestamp'];


        $r = [];
        $r['id'] = (int)$row['id'];
        $r['user'] = isset($users[$row['user_id']])? $users[$row['user_id']] : false;
        // $r['date'] = str_replace('-', '/', $row['created_at']);
        $r['date'] = date('Y/m/d H:i:s', $row['created_at']);
        $r['content'] = $row['content'];
        $messages[] = $r;
    }
    $messages = array_reverse($messages);

    list($channels, $description) = get_channel_list_info($channelId);
    return $this->view->render(
        $response,
        'history.twig',
        [
            'channels' => $channels,
            'channel_id' => $channelId,
            'messages' => $messages,
            'max_page' => $maxPage,
            'page' => $page
        ]
    );
})->add($loginRequired);

$app->get('/profile/{user_name}', function (Request $request, Response $response) {
    $userName = $request->getAttribute('user_name');
    list($channels, $_) = get_channel_list_info();

    $stmt = getPDO()->prepare("SELECT * FROM user WHERE name = ? LIMIT 1");
    $stmt->execute([$userName]);
    $user = $stmt->fetch();
    if (!$user) {
        return $response->withStatus(404);
    }

    $selfProfile = $request->getAttribute('user')['id'] == $user['id'];
    return $this->view->render(
        $response,
        'profile.twig',
        [
            'user' => $user,
            'channels' => $channels,
            'self_profile' => $selfProfile
        ]
    );
})->add($loginRequired);

$app->get('/add_channel', function (Request $request, Response $response) {
    list($channels, $_) = get_channel_list_info();
    return $this->view->render(
        $response,
        'add_channel.twig',
        [
            'channels' => $channels,
        ]
    );
})->add($loginRequired);

$app->post('/add_channel', function (Request $request, Response $response) {
    $name = $request->getParam('name');
    $description = $request->getParam('description');
    if (!$name || !$description) {
        return $response->withStatus(400);
    }

    $dbh = getPDO();
    $stmt = $dbh->prepare(
        "INSERT INTO channel (name, description, updated_at, created_at) ".
        "VALUES (?, ?, NOW(), NOW())"
    );
    $stmt->execute([$name, $description]);
    $channelId = $dbh->lastInsertId();
    return $response->withRedirect("/channel/$channelId", 303);
})->add($loginRequired);

$app->post('/profile', function (Request $request, Response $response) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withStatus(403);
    }

    $pdo = getPDO();
    $user = db_get_user($pdo, $userId);
    if (!$user) {
        return $response->withStatus(403);
    }

    $displayName = $request->getParam('display_name');
    $avatarName = null;
    $avatarData = null;

    $uploadedFile = $request->getUploadedFiles()['avatar_icon'] ?? null;
    if ($uploadedFile && $uploadedFile->getError() === UPLOAD_ERR_OK) {
        $filename = $uploadedFile->getClientFilename();
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        if (!in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
            return $response->withStatus(400);
        }

        $tmpfile = tmpfile();
        $metaData = stream_get_meta_data($tmpfile);
        $filepath = $metaData['uri'];

        $uploadedFile->moveTo($filepath);
        if (AVATAR_MAX_SIZE < filesize($filepath)) {
            return $response->withStatus(400);
        }
        $avatarData = file_get_contents($filepath);
        $avatarName = sha1($avatarData) . '.' . $ext;
    }

    if ($avatarName && $avatarData) {
        // $stmt = $pdo->prepare("INSERT INTO image (name, data, created_at) VALUES (?, ?, NOW())");
        // $stmt->bindParam(1, $avatarName);
        // $stmt->bindParam(2, $avatarData, PDO::PARAM_LOB);
        // $stmt->execute();

        // $redis = getRedisCli();
        // $redis->set("img_" . $avatarName, $avatarData);
        // $redis->set("img_time_". $avatarName, time());

        file_put_contents('../public/icons/'.$avatarName,$avatarData);

        $stmt = $pdo->prepare("UPDATE user SET avatar_icon = ? WHERE id = ?");
        $stmt->execute([$avatarName, $userId]);
    }

    if ($displayName) {
        $stmt = $pdo->prepare("UPDATE user SET display_name = ? WHERE id = ?");
        $stmt->execute([$displayName, $userId]);
    }

    return $response->withRedirect('/', 303);
})->add($loginRequired);

function ext2mime($ext)
{
    switch ($ext) {
        case 'jpg':
        case 'jpeg':
            return 'image/jpeg';
        case 'png':
            return 'image/png';
        case 'gif':
            return 'image/gif';
        default:
            return '';
    }
}

$app->get('/icons/{filename}', function (Request $request, Response $response) {
    $filename = $request->getAttribute('filename');

    $redis = getRedisCli();
    $modified = $redis->get("img_time_" . $filename);

    // $stmt = getPDO()->prepare("SELECT * FROM image WHERE name = ?");
    // $stmt->execute([$filename]);
    // $row = $stmt->fetch();
    $last_modified = gmdate("D, d M Y H:i:s T", strtotime($row['created_at']));
    $etag = sha1($row['id']);

    // リクエストヘッダの If-Modified-Since と If-None-Match を取得
    $if_modified_since = filter_input( INPUT_SERVER, 'HTTP_IF_MODIFIED_SINCE' );
    $if_none_match = filter_input( INPUT_SERVER, 'HTTP_IF_NONE_MATCH' );

    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $mime = ext2mime($ext);

    // Last-modified または Etag と一致していたら 304 Not Modified ヘッダを返して終了
    if ( $if_modified_since === $last_modified || $if_none_match === $etag ) {
      return $response->withStatus(304);
    }

    // if ($row && $mime) {
    if ($mime) {
        // $last_modified = gmdate("D, d M Y H:i:s T", strtotime($row['created_at']));
        // $etag = sha1($row['id']);
        //
        // // リクエストヘッダの If-Modified-Since と If-None-Match を取得
        // $if_modified_since = filter_input( INPUT_SERVER, 'HTTP_IF_MODIFIED_SINCE' );
        // $if_none_match = filter_input( INPUT_SERVER, 'HTTP_IF_NONE_MATCH' );

        // Last-modified または Etag と一致していたら 304 Not Modified ヘッダを返して終了
        // if ( $if_modified_since === $last_modified || $if_none_match === $etag ) {
        //   return $response->withStatus(304);
        // }
        $response->write($redis->get("img_" . $filename));
        // $response->write($row['data']);
        return $response
            ->withHeader('Content-type',  $mime)
            ->withHeader('Last-Modified', $last_modified)
            ->withHeader('ETag',          $etag)
            ->withHeader('Pragma',        'cache')
            ->withHeader('Cache-Control', 'public, max-age=8640000'); // １００日キャッシュしていい
    }
    return $response->withStatus(404);
});

$app->run();
