use serde::{Serialize, Deserialize};
use std::{convert::TryFrom};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Input {
	pub txid: String,
	pub vout: u32,
    pub script_sig: Vec<u8>,
	pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Output {
	pub amount: u64,
	pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BitcoinTransaction {
	pub version: u32,
	pub inputs: Vec<Input>,
	pub outputs: Vec<Output>,
	pub locktime: u32,
}

fn decode_compact_size(byte_tx: &mut Vec<u8>) -> u64 {

    let mut integer: u64 = u8::from_le_bytes(
        byte_tx.drain(..1).collect::<Vec<u8>>().try_into().unwrap()
    ) as u64;

    if integer == 0xFD {
        integer = u16::from_le_bytes(
            byte_tx.drain(..2).collect::<Vec<u8>>().try_into().unwrap()
        ) as u64;
    } else if integer == 0xFF {
        integer = u32::from_le_bytes(
            byte_tx.drain(..4).collect::<Vec<u8>>().try_into().unwrap()
        ) as u64;
    } else if integer == 0xFF {
        integer = u64::from_le_bytes(
            byte_tx.drain(..8).collect::<Vec<u8>>().try_into().unwrap()
        ) as u64;
    } else if integer > 0xFC {
        panic!("transaction can't have this much inputs!")
    }

    integer

}

fn encode_compact_size(integer: usize) -> Vec<u8> {

    if integer <= 0xFC {
        u8::try_from(integer).ok().unwrap().to_le_bytes().to_vec()
    } else if integer == 0xFD {
        u16::try_from(integer).ok().unwrap().to_le_bytes().to_vec()
    } else if integer == 0xFF {
        u32::try_from(integer).ok().unwrap().to_le_bytes().to_vec()
    } else if integer == 0xFF {
        u64::try_from(integer).ok().unwrap().to_le_bytes().to_vec()
    } else {
        panic!("transaction can't have this much inputs!")
    }

} 

impl BitcoinTransaction {
    
    fn from_hex(hex_tx: &str) -> BitcoinTransaction {

        let mut byte_tx = hex::decode(hex_tx).unwrap();

        let version = u32::from_le_bytes(
            byte_tx.drain(..4).collect::<Vec<u8>>().try_into().unwrap()
        );
        let marker = u8::from_le_bytes(
            byte_tx.drain(..1).collect::<Vec<u8>>().try_into().unwrap()
        );
        let flag = u8::from_le_bytes(
            byte_tx.drain(..1).collect::<Vec<u8>>().try_into().unwrap()
        );

        println!("{} {}", marker, flag);

        let input_counts = decode_compact_size(&mut byte_tx);

        let mut inputs = Vec::new();

        for _ in 0..input_counts {
            let txid = hex::encode::<Vec<u8>>(
                byte_tx.drain(..32).rev().collect::<Vec<u8>>().try_into().unwrap()
            );
            let vout = u32::from_le_bytes(
                byte_tx.drain(..4).collect::<Vec<u8>>().try_into().unwrap()
            );
            let script_sig_size = decode_compact_size(&mut byte_tx);
            let script_sig = byte_tx.drain(..script_sig_size as usize).collect::<Vec<u8>>().try_into().unwrap();
            let sequence = u32::from_le_bytes(
                byte_tx.drain(..4).collect::<Vec<u8>>().try_into().unwrap()
            );

            inputs.push(Input {
                txid,
                vout,
                script_sig,
                sequence,
                witness: Vec::new()
            });
        }

        let output_counts = decode_compact_size(&mut byte_tx);

        let mut outputs = Vec::new();

        for _ in 0..output_counts {
            let amount = u64::from_le_bytes(
                byte_tx.drain(..8).collect::<Vec<u8>>().try_into().unwrap()
            );
            let script_pubkey_size = decode_compact_size(&mut byte_tx);
            let script_pubkey: Vec<u8> = byte_tx.drain(..script_pubkey_size as usize).collect::<Vec<u8>>().try_into().unwrap();
            
            outputs.push(Output {
                amount,
                script_pubkey
            });
        }

        for i in 0..input_counts {
            let stack_items = decode_compact_size(&mut byte_tx);
            for _ in 0..stack_items {
                let size = decode_compact_size(&mut byte_tx);
                let item: Vec<u8> = byte_tx.drain(..size as usize).collect::<Vec<u8>>().try_into().unwrap();
                inputs[i as usize].witness.push(item);
            }
        }

        let locktime = u32::from_le_bytes(
            byte_tx.drain(..4).collect::<Vec<u8>>().try_into().unwrap()
        );

        BitcoinTransaction {
            version,
            inputs,
            outputs,
            locktime
        }

    }

    fn to_hex(self) -> String {

        let mut array = Vec::new();

        array.append(&mut self.version.to_le_bytes().to_vec());
        array.append(&mut 0_u8.to_le_bytes().to_vec());
        array.append(&mut 1_u8.to_le_bytes().to_vec());

        array.append(&mut encode_compact_size(self.inputs.len()));
        for input in self.inputs.iter() {
            let decoded_txid: Vec<u8> = hex::decode(&input.txid).unwrap();
            let mut serialized_txid: Vec<u8> = decoded_txid.into_iter().rev().collect();
            array.append(&mut serialized_txid);
            array.append(&mut input.vout.to_le_bytes().to_vec());
            array.append(&mut encode_compact_size(input.script_sig.len()));
            array.append(&mut input.script_sig.to_vec());
            array.append(&mut input.sequence.to_le_bytes().to_vec());
        }
        
        array.append(&mut encode_compact_size(self.outputs.len()));
        for output in self.outputs.iter() {
            array.append(&mut output.amount.to_le_bytes().to_vec());
            array.append(&mut encode_compact_size(output.script_pubkey.len()));
            array.append(&mut output.script_pubkey.to_vec());
        }
        
        for input in self.inputs.iter() {
            array.append(&mut encode_compact_size(input.witness.len()));
            for stack_item in input.witness.iter() {
                array.append(&mut encode_compact_size(stack_item.len()));
                array.append(&mut stack_item.to_vec());
            }
        }

        array.append(&mut self.locktime.to_le_bytes().to_vec());

        hex::encode(array)

    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_encode_hex() {
        let hex_tx = "0200000000010486f75e3d7ce24fcb26059afc14c680a8fe0a98b66df7a47d0ed7e3cb8da34b1c3900000017160014cfd979824f8f17f8cf2e797d4362f17ed2e96f33ffffffffc227020c54408e9735109084d2e7cd8460c861f643b289df5d91eedd11771f8e1b00000017160014cfd979824f8f17f8cf2e797d4362f17ed2e96f33ffffffff99af0c4277753078757fd4280f58c4f5a848d61632126bc7505f9a3a34b6f1540000000000ffffffff367412b606e0b84b8a798018abbf84eb32e67c4bf5de356afa212f6f87c49e3f0000000017160014cfd979824f8f17f8cf2e797d4362f17ed2e96f33ffffffff06b0040000000000001976a9141a047a70930d25e4262b50a408199768c927052088ac7803000000000000225120c20636bd7af9d6b0d451194a3d858b9083689b389bd68669623716ac09d4f3762d1002000000000017a914142f897c138fef28a2846d2c3b86de826e780e7687580200000000000017a9148d04dcc3e86612c668a0a973113586f266477d4587580200000000000017a9148d04dcc3e86612c668a0a973113586f266477d4587ef7f9e000000000017a9148d04dcc3e86612c668a0a973113586f266477d4587024830450221009a9eeb94d75ef168b7cc50483a87f7ee482206c505eacf51fe492a40d5d7e77a02206f386cf7531213406c9f22e53596f84de9a5abe77230295c2d62f635eb5313b501210338714323a3517d9652993c18c0f77f549bbcec1ff410690c8bc69a25deeef58902473044022043b41f2adb9198ba4c5a60977f0a2d073ea7835f85d2231b41caea6997886811022001f8d95aa6c9d241bb13af0ec2e3bee374a07c3168fc008ee26cf9a1d6d082b901210338714323a3517d9652993c18c0f77f549bbcec1ff410690c8bc69a25deeef58901412616cade598160a179d01e2c8b6374f78a44edbcd2a16f47873435b4e2c857d14384d992e33f922b584a7648759f126c4a3378a98085ed196ca865c2e48ce6f2830247304402204d41e149446bad0dee9489429d95eb7c7f9f21eb293ea9e4c981cd9acd2e80760220528d16031c77fae818987826c268f82da2686d3c1786bb64772933dbad3e0e6f01210338714323a3517d9652993c18c0f77f549bbcec1ff410690c8bc69a25deeef58900000000";

        let tx = BitcoinTransaction::from_hex(hex_tx);
        
        assert_eq!(hex_tx, &tx.to_hex())
    }

    #[test]
    fn address_to_witness() {
        assert!(true)
    }
}

fn main() {
    let hex_tx = "02000000000114bc2409241ae59543ea94433c650cd776519d52583d7164ee65f1c08288888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdfffffff2d56540d067239e4c82b953197b46ae9ce35a36eb10eababdcc298d88888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff332aff4eccd6b3ab50d3f1642fad56bcd0750dda505a4d74f1d7db8888888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffd875f0ec6dc8cbc35ffdb00a708a938804b838e77a921bf3c517cf8d88888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffe0a593bcc4215c599dcc1bee41518eafd160a0f856774e1b5e9ecd8288888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffda7eb959941f8ffe5d296520d5d31769ca459234b179090465e3b18388888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffe82282a44ad1077308e78bcd82caeec724f23f95d182e169924c758388888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffccae1ac18b19a0502ffb6b3084c1655a44b36abdc3089588d170488888888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff765fbc40113c8a8b529b2e874f3ac94df7afd99d6275cd74e90b4f8b88888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff23c026d1229d03b17cc894f26a4f6bd5cb9e1c4d621ddd8ab1f04b8688888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff8e916244b133848b640ef65c045b962da873aaaced798b5910b3868b88888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff1a8742bb34775c9f5bbee188f89d6c1bfc611b9d3d240aa560a1b58988888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffa2ca2408d4ed016b83656e4d5f2bcfdf7a95636f8a6a4bdc4c37068788888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff55a8b38f90a82c4ab451db3bec6a6ded3d6c95726ef5b804d62aad8a88888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff0e8ce046bcc9ace365a82b71a77bc4acb926805e17c766707dadadf788888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff9bd290d004bd801f56ba843ee57206a7dbff1ef1f325b79211ce91d688888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffbf25f9adaa259fa3bcab06f4100ccb6a2b5134e48d279f59754bcbf088888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffde0acb8d79117d219c0b746daed6a6326c494869cc63aeb5fa2691df88888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffffdbbadb9ba160f0f237e164a5e1fe73ccb756a7a9512977eb525d47f388888888020000001716001414fd7bf29cccd4d685568afb5303c99a5772d6e4fdffffff5a96b6021d0db0f5f5a1c5fb83a07ece97f7c8a1d0feb939170bcd368fa021a6160000001716001433f80862fed46d2b4b424c54fb51e6d8329fd3b0fdffffff0940420f000000000017a91413826f6fdf91f05e6d4d7eacf51facc3307807668740420f000000000017a91413bdbc9a53538d2eac24eb10c28712121b1827208750040b000000000017a914819815432fc71631ca70fc12378b4c16c3b077a087500a0a00000000001976a914b7f08236a9162762a6782beabecf331e2b89fb2288ac3481090000000000160014492c10ec06b3b2c56a10f00ed28b1c6e872303b0512b0900000000001976a9141e47cf19dacfb77286ef950da5ec45870195156b88ac08bc0800000000001976a9145d92e8d06904abfe164fe3536d6f4ad395e45fe388ac8c4b00000000000017a9141597fd9505a1b941091acda336551b71353e532f8726283d3b000000001976a914cebb2851a9c7cfe2582c12ecaf7f3ff4383d1dc088ac024730440220154c62d8db054ca73932d7a57a673f4c8756c71b3b109efcbfa672c52b436cf902201105490711830b1b61ea09865627c1b52ede62da7665be9936a3c8dbc1c320b70121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a357190247304402203e16ab2db63b7c552906928208f8fd9d4608e83a38a52ed97661837500f352fc02200999e8a4b32118e17c5aee99d9f44ec2d6f4d80ac082b387266d56b43f9b25fc0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022022f706e6ce57562b60759be9b0c2a48937b68c320f2a94a46b0edca7cd6b69990220218ec9e32cc954fc55ed3082ef805c1f69190473df1331078005b171d058dab00121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a357190247304402202e59a6dc4ed7d65bf2d552202cd43ee923532d2cf1b18db7ab6b1b104765ae9102207e2ea7a0f75c444595412dd8b0ba352bf3e479a17d6eb1dba7c3420c8860e2fd0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022045e17cb7266fd15be3acc9b3125cd7b50a7d42720839dcb29f3964a7f75cbcc30220080817083eb67eed230759fab175915a217bbbdb2d1d8b935eac864eaf1306860121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022027065533f6100e6ca1e4a0b6d5dd1c54e9c29ab3f35f6ea99f7c9aa785a1c816022017e1006aef1962c8390345f4797b54bed352958f94f5716dbc362ae398718bdb0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022008c02254589c815bf130365a1f940af14f67488804a483480d2ab2f38f763b51022015fba3682ada98eff85d76a869ca35ba9d509c06d102ff216dbe105a5f5df0a00121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a35719024730440220114aa4c955054af33d1272fbed5ed33eff0082608c36e6a9910be4a81acb642f02203ab62488e529006054885143ac0078e46f26c7cbf0927b471d1599fae07657560121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a357190247304402207ceb941fdd9d0eac01e879a1d57cded327b4d38713c85067fd50b48d9aa63e7b02200ffe61f3d69d8612f12f86c7fcc9460b5611ceab5a1a42abc4e589e03af761770121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022030d45b185c55683a149acb2aa7fc9506402b210f9a6d4a4c05648b814f2fdd59022074f325e1dd707fdddf1b6981be9e4e3dda3e7456857ea49de804e34c665bf8ce0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022005c9f14bfdf738a72aaddafe81cebacdc13fc20e34b790a6fe06df57f21237610220505c40abfcbe0cef2193f0d1f535e959a06c965ec48404fcf868895deb9b01200121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022077ffe921cc6467c1313ba4513a47037496d6681ba856949f588acebe247068bd022048636409b1e44f609ff59c36a5dda598af3be701ae41e3679795dfa6eff3fe4a0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a357190247304402206520ace4142dfaca6596128bb1e04f62d12b43b0dd0a5ed956df31b6c1f5a05f02202c2fd5a2aff00c8618617f4321a9f7739b54f948dca0a6cf8ecb532806fa5a650121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a35719024730440220209ee9ef2558bcec02f850fe518e1549c70a2033d79d851f98f8bfb1da85e6cb022054fc888a42956b819969c20b0ade31959c3c9b937954738560b652ae264f1d490121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022039e185d117d5d329682b0d585b54df281df2941b69600bd6861e1da23738530f02207108c316dd7842db34f807422330d1e74a7ee308a28a5dee5a6aa25177263a380121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a3571902473044022019388dbc43df343f1ed2934512002b0db9de71751b17dcaa077ecb5d7597292302203e4fc039cc03751716c8eea3421e6dfcc5be2d4aab986b4483943800b189fd900121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a35719024730440220637565a2a1807213f14dd793f0e45903dcf982e043c44dedf9274c65ca03296f022019930b8a96370d93e823af6835660aa1f33c7c715b2adf33b2b179a2b0a808bc0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a35719024730440220745dd8eca570f957984b3e91b6e591e9368131f5c9f960d9cd381a689459b173022062c144a67f6ea3cc680035716b1f0413342684dc005fbda00db2a40f5cffa64c0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a35719024730440220711884bf23ca956dd00168e4c174f0b63008032797bbe2b47b1c3f1786d406ea0220440d578d5930750b7e0acb44b4c9c1b5ebd7567d20d500c9633032893c39c12a0121021374056db26c3f35632eb16718f4f7c3e9db07a89fb2c2a3c92606e4f3a35719024730440220053b9de3f3660535e63bb8cea9a5ce1c6d2d5d67616ceb3305139f0c9958e81b02205bf0640acaf7971038f40fbe5545b78159d0c932a3b4070f045bbd0f5141e3f80121023343bdc7771cb817417cea1d39cd85c5ff27b88a1393437a245428aacbf6d4c000000000";

    let tx = BitcoinTransaction::from_hex(hex_tx);
    println!("{:?}", tx.outputs[0].script_pubkey)
}