<?php

require '../pwpusher_private/config.php';
require '../pwpusher_private/database.php';
require '../pwpusher_private/mail.php';
require '../pwpusher_private/security.php';
require '../pwpusher_private/input.php';
require '../pwpusher_private/CAS/CAS.php';

function checkRequest()
{
    $errors = array();
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $errors[] = 'Only POST is supported';
    }
    if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
        $errors[] = 'Only application/json is supported';
    }
    if (count($errors)) {
        http_response_code(400);
        exit(json_encode(['errors' => $errors]));
    }
}

$errors = [];

function getError($error)
{
    return $error.PHP_EOL;
}

function translate($phrase)
{
    require_once '../pwpusher_private/config.php';
    require_once '../pwpusher_private/languages/en.php';

    return ${$phrase};
}

header('Content-Type: application/json');

// Capture the errors

checkRequest();
ob_start();
$arguments = json_decode(file_get_contents('php://input'), true);
$defaults = array('cred' => '');
$arguments = array_merge($defaults, $arguments);
checkInput($arguments);
$errors = ob_get_clean();
ob_end_clean();

$errors = array_filter(explode(PHP_EOL, trim($errors)));

//Check key size to ensure it meets AES requirements.
if (!correctKeySize()) {
    $errors[] = getError(translate('databaseErrorGeneric'));
    error_log("PHPassword Configuration Error: Encryption key must be of length 16, 24, or 32.\n");
}

if (count($errors)) {
    http_response_code(400);
    exit(json_encode(array('errors' => $errors)));
}

//Else if POST arguments exist and have been verified, process the credential
//Encrypt the user's credential.
$encrypted = encryptCred($arguments['cred']);

//Wipe out the variable with the credential.
unset($arguments['cred']);

//Create a unique identifier for the new credential record.
$id = getUniqueId();

//Insert the record into the database.
insertCred(hashId($id, $salt), $encrypted, $arguments['time'], $arguments['views']);

//Generate the retrieval URL.
$url = sprintf(
    'https://%s%s?id=%s',
    $_SERVER['HTTP_HOST'],
    htmlspecialchars($_SERVER['PHP_SELF']),
    urlencode($id)
);

//Send email if configured and if the email has been filled out
if ($enableEmail && !empty($arguments['destemail'])) {
    mailURL(
        $url,
        $arguments['destemail'],
        $arguments['destname'],
        calcExpirationDisplay($arguments['time']),
        $arguments['views']
    );
}

$url = str_replace('api.php', 'pw.php', $url);
//If the URL is configured to be displayed print the URL and associated functions
if ($displayURL) {
    $msg = array('url' => $url);
} else {
    $msg = array('message' => getSuccess(translate('credentialsCreated')));
}

http_response_code(201);
exit(json_encode($msg));
