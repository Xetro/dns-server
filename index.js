const dns2 = require('dns2');
const { Packet } = dns2;

const MongoClient = require('mongodb').MongoClient;

const dnsPort = 53;

const uri = "mongodb://localhost:27017";
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });


const dns24ur = [
  {
    name: 'www.24ur.com',
    type: Packet.TYPE.CNAME,
    class: Packet.CLASS.IN,
    ttl: 120,
    domain: "sni.star.24ur.com.c.footprint.net"
  },
  {
    name: 'wsni.star.24ur.com.c.footprint.net',
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 160,
    address: "8.238.30.124"
  },
  {
    name: 'wsni.star.24ur.com.c.footprint.net',
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 160,
    address: "8.248.115.252"
  },
  {
    name: 'wsni.star.24ur.com.c.footprint.net',
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 160,
    address: "8.241.9.252"
  },
  {
    name: 'wsni.star.24ur.com.c.footprint.net',
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 160,
    address: "67.26.73.252"
  },
  {
    name: 'wsni.star.24ur.com.c.footprint.net',
    type: Packet.TYPE.A,
    class: Packet.CLASS.IN,
    ttl: 160,
    address: "8.253.207.117"
  },
];



const dnsOptions = {
  dns: '8.8.8.8',
};

const dns = new dns2(dnsOptions);

const savedRequests = {};
const blockPage = "89.212.183.250";
const blockedDomains = ['disney.com', 'www.disney.com', 'www.24ur.com', 'vreme.si', 'www.vreme.si'];

client.connect(async err => {
  const collection = await client.db("test").collection("whitelist");

  const server = dns2.createUDPServer(async (request, send, rinfo) => {
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;
    const { name } = question;

    let responseIP;
    let answers;


    if (name === "www.unsafe-24ur.com") {
      console.log('UNSAFE DETECTED!');
      const dnsResponse = await dns.resolveA('www.24ur.com');

      let cname = [{
        name,
        type: Packet.TYPE.CNAME,
        class: Packet.CLASS.IN,
        ttl: 10,
        domain: "www.24ur.com"
      }];


      // answers = cname.concat(dns24ur);
      answers = cname.concat(dnsResponse);

    } else if (name === "a1-blockpage.com" || name === "www.a1-blockpage.com") {

      console.log('A1-blockpage resolution requested');
      answers = [{
        name,
        type: Packet.TYPE.A,
        class: Packet.CLASS.IN,
        ttl: 10,
        address: blockPage
      }]
    }

    else if (blockedDomains.includes(name)) {


      console.log(`REQUESTED BLOCKED DOMAIN: `, request.questions[0]);


      let doc = await collection.findOne({
        user: {
          $eq: rinfo.address
        }
      });

      if (doc && doc.whitelist.find(record => record.domain === name)) {
        console.log("DOMAIN WHITELISTED FOR USER!");


        if (false && name === "www.24ur.com") {
          answers = dns24ur;
        } else {
          const dnsResponse = await dns.resolveA(name);
          answers = dnsResponse.answers
        }
      }


      else {

        console.log('SENDING BLOCKPAGE');

        answers = [
          {
            name,
            type: Packet.TYPE.CNAME,
            class: Packet.CLASS.IN,
            ttl: 10,
            domain: "www.a1-blockpage.com"
          }
        ];
      }

    } else {

      if (false && name === "www.24ur.com") {
        answers = dns24ur;
      } else {

        const dnsResponse = await dns.resolveA(name);
        answers = dnsResponse.answers
      }

    }

    // console.log('Saved: ', savedRequests);

    // console.log('RESPONSE: ', response);
    // console.log('ANWSERS: ', answers);



    response.answers = answers;

    // console.log('RESPONSE AFTER: ', response);

    send(response);
  });

  server.on('request', (request, response, rinfo) => {
    console.log(request.header.id, request.questions[0]);
  });

  server.listen(dnsPort, () => console.log(`SERVER IS RUNNING ON: `, dnsPort));









})






