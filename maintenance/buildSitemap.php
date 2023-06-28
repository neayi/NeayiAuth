<?php

$root = dirname(dirname(dirname(__DIR__))) . "/images/*/sitemap/sitemap-index-*.xml";
$sitemaps = glob($root);

$sitemapXML = '<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';

foreach ($sitemaps as $url)
{
    $url = str_replace('/var/www/html/', 'https://fr.tripleperformance.ag/', $url);
    $date = date('Y-m-dTH:i:s');
    $sitemapXML .= '
	<sitemap>
		<loc>'.$url.'</loc>
        <lastmod>'.$date.'Z</lastmod>
	</sitemap>';
}

$sitemapXML .= "
</sitemapindex>";

file_put_contents('/var/www/html/sitemap.xml', $sitemapXML);
