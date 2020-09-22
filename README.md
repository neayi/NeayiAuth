# NeayiAuth

The **NeayiAuth** extension enables us to delegate authentication to our Laravel back-office.

This extension requires PluggableAuth to be installed first. 

# To install
* Add the extension in the extensions folder of your mediawiki setup
* Add wfLoadExtension( 'NeayiAuth' );
* You will also need the following settings: 
$wgOAuthRedirectUri = 'https://pratiques.dev.tripleperformance.fr/index.php/Special:PluggableAuthLogin';
$wgPluggableAuth_EnableAutoLogin = false;
$wgPluggableAuth_EnableLocalLogin = true;
$wgPluggableAuth_EnableLocalLogin = false;
$wgOAuthUri = 'http://dev.core.tripleperformance.com:8008/login?&';
$wgOAuthUserApiByToken = 'http://neayi_nginx/api/user?&';

* Now run update.php in the maintenance folder (this is to create the table neayiauth)


