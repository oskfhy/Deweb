<?php
    class authCode {
        public $ttl;//到期时间 时间格式：20120101(年月日)
        public $key_1;//密钥1
        public $key_2;//密钥2
        public $td;
        public $ks;//密钥的长度
        public $iv;//初始向量
        public $salt;//盐值（某个特定的字符串）
        public $encode;//加密后的信息
        public $return_array = array(); //返回带有MAC地址的字串数组
        public $mac_addr;//mac地址
        public $filepath;//保存密文的文件路径
        public function __construct($key=''){
		$this->salt="~!@#$";
		$this->key	=	$key;
        }
        /**
         * 对明文信息进行加密
         * @param $key 密钥
         */
        public function encode($content) {
            $this->td = mcrypt_module_open(MCRYPT_DES,'','ecb',''); //使用MCRYPT_DES算法,ecb模式
            $size=mcrypt_enc_get_iv_size($this->td);//设置初始向量的大小
            $this->iv = mcrypt_create_iv($size, MCRYPT_RAND);//创建初始向量
            $this->ks = mcrypt_enc_get_key_size($this->td);//返回所支持的最大的密钥长度（以字节计算）
            $this->key_1 = substr(md5(md5($this->key).$this->salt),0,$this->ks);
            mcrypt_generic_init($this->td, $this->key_1, $this->iv); //初始处理
            $this->encode = base64_encode(mcrypt_generic($this->td, $content));
            mcrypt_generic_deinit($this->td);
            return $this->encode;
        }
        /**
         * 对密文进行解密
         * @param $key 密钥
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
