use serde::{Serialize, Deserialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Input {
	pub txid: String,
	pub vout: u32,
    pub script_sig: Vec<u8>,
	pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Output {
	pub amount: u64,
	pub script_pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
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
    
    pub fn from_hex(hex_tx: &str) -> BitcoinTransaction {

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
}