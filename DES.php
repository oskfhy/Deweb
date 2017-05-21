<?php
    class authCode {
        public $ttl;//����ʱ�� ʱ���ʽ��20120101(������)
        public $key_1;//��Կ1
        public $key_2;//��Կ2
        public $td;
        public $ks;//��Կ�ĳ���
        public $iv;//��ʼ����
        public $salt;//��ֵ��ĳ���ض����ַ�����
        public $encode;//���ܺ����Ϣ
        public $return_array = array(); // ���ش���MAC��ַ���ִ����� 
        public $mac_addr;//mac��ַ
        public $filepath;//�������ĵ��ļ�·��
        public function __construct(){
            //��ȡ�����ַ
            $this->mac_addr=$this->getmac(PHP_OS);
            $this->filepath="./licence.txt";
            $this->ttl="20171121";//����ʱ��
            $this->salt="~!@#$";//��ֵ������������ĵİ�ȫ��
//            echo "<pre>".print_r(mcrypt_list_algorithms ())."</pre>";
//            echo "<pre>".print_r(mcrypt_list_modes())."</pre>";
        }
        /**
         * ��������Ϣ���м���
         * @param $key ��Կ
         */
        public function encode($key) {
            $this->td = mcrypt_module_open(MCRYPT_DES,'','ecb',''); //ʹ��MCRYPT_DES�㷨,ecbģʽ
            $size=mcrypt_enc_get_iv_size($this->td);//���ó�ʼ�����Ĵ�С
            $this->iv = mcrypt_create_iv($size, MCRYPT_RAND);//������ʼ����
            $this->ks = mcrypt_enc_get_key_size($this->td);//������֧�ֵ�������Կ���ȣ����ֽڼ��㣩
            $this->key_1 = substr(md5(md5($key).$this->salt),0,$this->ks);
            mcrypt_generic_init($this->td, $this->key_1, $this->iv); //��ʼ����
            //Ҫ���浽����
            $con=$this->mac_addr.$this->ttl;
            //����
            $this->encode = mcrypt_generic($this->td, $con);   
            //��������
            mcrypt_generic_deinit($this->td);
            //�����ı��浽�ļ���
            $this->savetofile();
        }
        /**
         * �����Ľ��н���
         * @param $key ��Կ
         */
        public function decode($key) {
            try {
                if (!file_exists($this->filepath)){
                    throw new Exception("��Ȩ�ļ�������");
                }else{//�����Ȩ�ļ����ڵĻ������ȡ��Ȩ�ļ��е�����
                    $fp=fopen($this->filepath,'r');
                    $secret=fread($fp,filesize($this->filepath)); 
                    $this->key_2 = substr(md5(md5($key).$this->salt),0,$this->ks);
                    //��ʼ���ܴ���
                    mcrypt_generic_init($this->td, $this->key_2, $this->iv);
                    //����
                    $decrypted = mdecrypt_generic($this->td, $secret);
                    //���ܺ�,���ܻ��к�����\0,��ȥ��   
                    $decrypted=trim($decrypted) . "\n";   
                    //����
                    mcrypt_generic_deinit($this->td);   
                    mcrypt_module_close($this->td);
                    return $decrypted;        
                }
            }catch (Exception $e){
                echo $e->getMessage();
            }
        }
        /**
         * �����ı��浽�ļ���
         */
        public function savetofile(){
            try {
                $fp=fopen($this->filepath,'w+');
                if (!$fp){
                    throw new Exception("�ļ�����ʧ��");
                }
                fwrite($fp,$this->encode);
                fclose($fp);
            }catch (Exception $e){
                echo $e->getMessage();
            }
        }
        /**
         * ȡ�÷�������MAC��ַ
         */
        public function getmac($os_type){ 
             switch ( strtolower($os_type) ){ 
                      case "linux": 
                                $this->forLinux(); 
                                break; 
                      case "solaris": 
                                break; 
                      case "unix": 
                                 break; 
                       case "aix": 
                                 break; 
                       default: 
                               $this->forWindows(); 
                               break; 
              }
              $temp_array = array(); 
              foreach( $this->return_array as $value ){
                        if (preg_match("/[0-9a-f][0-9a-f][:-]"."[0-9a-f][0-9a-f][:-]"."[0-9a-f][0-9a-f][:-]"."[0-9a-f][0-9a-f][:-]"."[0-9a-f][0-9a-f][:-]"."[0-9a-f][0-9a-f]/i",$value,$temp_array )){
                            $mac_addr = $temp_array[0]; 
                            break; 
                       }
              }
              unset($temp_array); 
              return $mac_addr; 
         }
         /**
          * windows��������ִ��ipconfig����
          */
         public function forWindows(){ 
              @exec("ipconfig /all", $this->return_array); 
              if ( $this->return_array ) 
                       return $this->return_array; 
              else{ 
                       $ipconfig = $_SERVER["WINDIR"]."\system32\ipconfig.exe"; 
                       if ( is_file($ipconfig) ) 
                          @exec($ipconfig." /all", $this->return_array); 
                       else 
                          @exec($_SERVER["WINDIR"]."\system\ipconfig.exe /all", $this->return_array); 
                       return $this->return_array; 
              }
         }
         /**
          * Linux��������ִ��ifconfig����
          */
         public function forLinux(){ 
              @exec("ifconfig -a", $this->return_array); 
              return $this->return_array; 
         }
    }
    $code=new authCode();
    //����
    $code->encode("~!@#$%^");
    //����
    echo $code->decode("~!@#$%^");
?>