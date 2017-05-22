<?php
    class authCode {
        public $ttl;//??ǚ???±?乱???20120101(???)
        public $key_1;//??1
        public $key_2;//??2
        public $td;
        public $ks;//????¤?
        public $iv;//???
        public $salt;//???¨????¨?????
        public $encode;//???????
        public $return_array = array(); // ?????C????????? 
        public $mac_addr;//mac???
        public $filepath;//±???τ???????
        public function __construct($key=''){
		$this->salt="~!@#$";
		$this->key	=	$key;
        }
        /**
         * ?????????
         * @param $key ??
         */
        public function encode($content) {
            $this->td = mcrypt_module_open(MCRYPT_DES,'','ecb',''); //??MCRYPT_DES??¨,ecb??
            $size=mcrypt_enc_get_iv_size($this->td);//????????
            $this->iv = mcrypt_create_iv($size, MCRYPT_RAND);//???¨???
            $this->ks = mcrypt_enc_get_key_size($this->td);//??????????????¤??¨??????
            $this->key_1 = substr(md5(md5($this->key).$this->salt),0,$this->ks);
            mcrypt_generic_init($this->td, $this->key_1, $this->iv); //????m
            $this->encode = base64_encode(mcrypt_generic($this->td, $content));
            mcrypt_generic_deinit($this->td);
            return $this->encode;
        }
        /**
         * ???????
         * @param $key ??
         */
        public function decode($content) {
            try {
                    $secret=base64_decode($content); 
                    $this->key_2 = substr(md5(md5($this->key).$this->salt),0,$this->ks);
                    mcrypt_generic_init($this->td, $this->key_2, $this->iv);
                    $decrypted = mdecrypt_generic($this->td, $secret);
                    $decrypted=trim($decrypted) . "\n";   
                    mcrypt_generic_deinit($this->td);   
                    mcrypt_module_close($this->td);
                    return $decrypted;        
            }catch (Exception $e){
                echo $e->getMessage();
            }
        }
    }
    $code=new authCode("This is key string");
    echo $code->encode("yingjiechen");
    echo $code->decode("gLDMdAJ9TJXSnnuH0q9FCQ==");
?>
