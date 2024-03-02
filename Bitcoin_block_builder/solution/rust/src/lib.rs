use std::error::Error;
use std::fs::File;
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::collections::BinaryHeap;
use std::cmp::Ordering;
use std::fs::write;

#[derive(Debug, Deserialize)]
struct Data {
    txid: String,
    fee: u64,
    weight: u64,
    parents: Option<Vec<String>>,
}

#[derive(Eq, PartialEq)]
struct TxNode {
    txid: String,
    fee: u64,
    weight: u64,
}

impl Ord for TxNode {

    fn cmp(&self, other: &Self) -> Ordering {
        let self_ratio = self.fee as f64 / self.weight as f64;
        let other_ratio = other.fee as f64 / other.weight as f64;
        self_ratio.partial_cmp(&other_ratio).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for TxNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn write_to_file(block: Vec<String>, filename: &str) -> Result<(), Box<dyn Error>> {
    let contents = block.join("\n");
    write(filename, contents)?;
    Ok(())
}

pub fn start() {

  let file = File::open("../../../mempool.csv").unwrap();
  let mut rdr = csv::ReaderBuilder::new()
    .has_headers(false)
    .from_reader(file);
  //helps in identifying the node by the txid
  let mut tx_to_node: HashMap<String, TxNode> = HashMap::new();

  //helps in identifying the number of incoming edges to a node to check if parentless 
  let mut tx_to_incomings: HashMap<String, u64> = HashMap::new();

  //helps in traversing the graph
  let mut tx_to_children: HashMap<String, Vec<String>> = HashMap::new();
  
  //get the data from csv file and store it in the hashmaps

  for result in rdr.deserialize() {

    let record: Data = result.unwrap();
    tx_to_node.insert(record.txid.clone(), TxNode{txid: record.txid.clone(), fee: record.fee, weight: record.weight});
    tx_to_incomings.insert(record.txid.clone(), record.parents.clone().unwrap_or_else(Vec::new).len() as u64);

    if let Some(parents) = &record.parents {
        for parent in parents {
            let children = tx_to_children.entry(parent.clone()).or_insert(Vec::new());
            children.push(record.txid.clone());
        }
    }
  }

  let mut heap = BinaryHeap::new();

    //push all the parentless nodes into the heap
    for (txid, incomings) in tx_to_incomings.iter() {
      if *incomings == 0 {
        heap.push(tx_to_node.get(txid).unwrap());
      }
    }
    
    //initialize the block
    let mut block: Vec<String> = Vec::new();
    let mut block_weight: u64 = 0;
    let mut block_fee: u64 = 0;

    let MAX_WEIGHT: u64 = 4000000; 

    //traverse the graph
    while !heap.is_empty() {
      
      //get node  
      let node = heap.pop().unwrap();
      
      // if the weight of the block after adding the node is less than the max weight, add the node to the block
      if block_weight + node.weight <= MAX_WEIGHT {
        
        block_weight += node.weight;
        block_fee += node.fee;
        block.push(node.txid.clone());

        if let Some(children) = tx_to_children.get(&node.txid) {

          for child in children {
            let mut incomings = tx_to_incomings.get_mut(child).unwrap();
            *incomings -= 1;
            if *incomings == 0 {
              heap.push(tx_to_node.get(child).unwrap());
            }
          }
        }

      }
    }

    //print the block data except the transactions
    println!("Block weight: {}", block_weight);
    println!("Block fee: {}", block_fee);
    println!("Number of transactions: {}", block.len());
    println!("Packing efficiency: {}", block_weight as f64 / MAX_WEIGHT as f64);

    //write the block to a file
    write_to_file(block, "../../block.txt").unwrap();

}