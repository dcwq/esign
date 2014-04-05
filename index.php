<!DOCTYPE HTML>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en" dir="ltr">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
</head>
<body>
<?php

require 'libs/xmlseclibs.php';
require 'libs/checker.php';

/* PLIKI DO TESTOWANIA */

$filename = 'data/1.XAdES';
//$filename = 'data/2.XAdES';
//$filename = 'data/3.xml';

/* /PLIKI DO TESTOWANIA */

$checker = new checker($filename);

//check is valid
if ($checker->isValid())
{
    echo '<h1 style="background: #5cb85c;">Signature validated</h1>';
}
else
{
    echo '<h1 style="background: #ef6155;">Signature failure</h1>';
}

//get certificate info
$info = $checker->getCertInfo();

echo '<h1>Certificate info</h1>';

foreach ($info as $space=>$spaceAttributes)
{
    echo '<h2>'.strtoupper($space).'</h2>';

    echo '<table border="1">';
    foreach ($spaceAttributes as $attribute => $attributeValue)
    {
        echo '<tr><td>'.$attribute.'</td><td>'.$attributeValue.'</td></tr>';
    }
    echo '</table>';
}

?>
</body>
</html>