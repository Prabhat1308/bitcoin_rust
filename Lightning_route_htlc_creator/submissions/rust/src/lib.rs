use lightning_invoice::Bolt11Invoice;
use lightning::util::ser::Writeable;
use std::str::FromStr;
use std::fmt;
use hex;


impl fmt::Display for DataOut {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{},{},{},{},{}", self.path_id, self.channel_name, self.htlc_amount_msat,self.htlc_expiry,self.tlv)
    }
}

struct Data {
    path_id: u32,
    channel_name: String,
    cltv_delta: u32,
    fee_base_msat: u32,
    fee_proportional_ppm: u32,
}

struct DataOut {
    path_id: u32,
    channel_name: String,
    htlc_amount_msat: u64,
    htlc_expiry: u32,
    tlv: String,
}

pub fn run(path: &str, payment_request: &str, block_height: u64){

    let mut data = Vec::new();
    let mut reader = csv::Reader::from_path(path).unwrap();

    let mut init : u32 = 0;
     
    let mut temp_vec: Vec<Data> = Vec::new();

    for result in reader.records() {

        let record = result.unwrap();

        let path_id: u32 = record[0].parse().unwrap();
        let channel_name: String = record[1].parse().unwrap();
        let cltv_delta: u32 = record[2].parse().unwrap();
        let fee_base_msat: u32 = record[3].parse().unwrap();
        let fee_proportional_ppm: u32 = record[4].parse().unwrap(); 
        
        if path_id != init {
            data.push(temp_vec);
            temp_vec = Vec::new();  //empty temp_vec
            init = path_id; 
        }

        let data_temp = Data {
            path_id,
            channel_name,
            cltv_delta,
            fee_base_msat,
            fee_proportional_ppm,
        };

        temp_vec.push(data_temp);
    }

    if temp_vec.len() > 0 {
        data.push(temp_vec);
    }
    
    init = init + 1;

    let invoice = Bolt11Invoice::from_str(payment_request).unwrap();

    let final_amount_to_pay = invoice.amount_milli_satoshis().unwrap();
    
    let final_expiry = invoice.min_final_cltv_expiry_delta();
    
    
    let payment_secret = invoice.payment_secret();
    let payment_secret_in_vecu8 = payment_secret.encode();
    let payment_secret_in_hex = hex::encode(payment_secret_in_vecu8);

    let mut tlv_for_last_node: String = String::from("NULL");

    if init > 1 {

        let total_msat_to_bytes = final_amount_to_pay.to_be_bytes();
        let total_msat_in_hex = hex::encode(total_msat_to_bytes);
        let prefix  = "00000000000000080000000000000028";
        // concatenate prefix , payment_secret and total_msat_in_hex
        tlv_for_last_node = format!("{}{}{}", prefix, payment_secret_in_hex, total_msat_in_hex);
    }

    let mut data_out_vec = Vec::new();
        
    for path in data {
        
        let mut channel_vec = path;
        
        channel_vec.reverse();
        
        let mut temp_channel_vec : Vec<DataOut> = Vec::new();

        let mut amount = final_amount_to_pay / init as u64 ;
        let mut expiry = final_expiry + block_height;
        let mut prv_ppm = 0 as u64;
        let mut prv_channel_base = 0 as u64;
        for (index,channel) in channel_vec.iter().enumerate() {
           
            let path_id = channel.path_id;

            let channel_name = &channel.channel_name;
     
            //htlc amount calculation 
            let mut htlc_amount : u64 = 0;

            if index == 0 {
             htlc_amount = amount ;
             prv_ppm = channel.fee_proportional_ppm  as u64 ;
             prv_channel_base = channel.fee_base_msat as u64;
            }else{
             htlc_amount = amount + prv_channel_base + ( prv_ppm * amount / 1000000) as u64;
             prv_ppm = channel.fee_proportional_ppm  as u64 ;
             prv_channel_base = channel.fee_base_msat as u64;
             amount = htlc_amount;
            }
     
             //htlc expiry calculation
             let htlc_expiry = expiry ;
             expiry = htlc_expiry + channel.cltv_delta as u64;
     
             let mut tlv = "NULL";

             if index == 0 {
                tlv = &tlv_for_last_node;
             }
             
             let data_out = DataOut {
                 path_id : path_id,
                 channel_name : channel_name.to_string(),
                 htlc_amount_msat: htlc_amount,
                 htlc_expiry: htlc_expiry.try_into().unwrap(),
                 tlv: tlv.to_string(),
             };
           
           temp_channel_vec.push(data_out);
        }

        temp_channel_vec.reverse();

        data_out_vec.push(temp_channel_vec);

    }

    let mut linear_data_out_vec = Vec::new();

    for path in data_out_vec {

        for channel in path {
            linear_data_out_vec.push(channel);
        }

    }

    //     // writing to a .txt file
    //     let content = linear_data_out_vec
    //     .iter()
    //     .map(|data_out| data_out.to_string())  // Assuming DataOut implements ToString
    //     .collect::<Vec<_>>()
    //     .join("\n");
       
    // // Write the content to a new .txt file
    // fs::write("output.txt", content).expect("Unable to write file");   

    // output the contents of linear_data_out_vec
    
    for data_inside in linear_data_out_vec {
        println!("{}",data_inside);
    }
}