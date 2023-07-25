#include <iostream>
#include <fmt/core.h>
#include <fmt/color.h>
#include <cryptopp/des.h>
#include <cryptopp/base64.h>
#include <mpi.h>

void DES_decrypt(const char *keyString, CryptoPP::byte *block, size_t length, CryptoPP::byte *out_buffer) {
    CryptoPP::byte key[CryptoPP::DES::KEYLENGTH];
    std::memcpy(key, keyString, CryptoPP::DES::KEYLENGTH);

    auto cipher = std::make_shared<CryptoPP::DESDecryption>(key, CryptoPP::DES::KEYLENGTH);

    int steps = length / cipher->BlockSize();
    for (int i = 0; i < steps; i++) {
        int offset = i * cipher->BlockSize();

        cipher->ProcessBlock(block + offset, out_buffer + offset);
    }
}

std::string to_base64(std::string str) {
    std::string ret;
    CryptoPP::StringSource ss(str, true,
                              new CryptoPP::Base64Encoder(
                                      new CryptoPP::StringSink(ret)
                              )
    );
    return ret;
}

std::string from_base64(std::string str) {
    std::string ret;
    CryptoPP::StringSource ss(str, true,
                              new CryptoPP::Base64Decoder(
                                      new CryptoPP::StringSink(ret)
                              )
    );
    return ret;
}

int main(int argc, char** argv) {
    // texto en formato BASE64
    std::string cipher_text = "3CC4M6vAfC92tf7vIkRzXC9bOZKtT6q6jz0ewyv4niBO7M8jHcdmi+h2yNq4KRJO2TzgL0dZbcwnrZMHClLJHQ==";
    const char* text_to_find = "cryptographic";

    MPI_Init(&argc, &argv);

    int rank_id;
    int nprocs;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank_id);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

    long block_size = LLONG_MAX/nprocs;

    long start_index = rank_id*block_size;
    long end_index = (rank_id+1)*block_size;

    if(rank_id==6) {
        start_index = 7523094288207667809-10;
    }

    fmt::print(fg(fmt::color::gray), "rank {} check from {} to {}\n",
               rank_id,start_index,end_index);

    long key_found = 0;
    long test_key;

    MPI_Request  req;
    MPI_Status st;
    MPI_Irecv(&key_found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);

    std::string text = from_base64(cipher_text);
    int clen = text.size();
    CryptoPP::byte* ptr = (CryptoPP::byte* )text.c_str();

    std::vector<CryptoPP::byte> out_buffer(clen, 0);

    long cc = 0;
    int flag;
    for(test_key=start_index;test_key<end_index && !key_found;test_key++) {
        DES_decrypt((char *)&test_key, ptr, clen,out_buffer.data() );

        if( std::strstr((char *)out_buffer.data(), text_to_find) ) {
            key_found = test_key;

            fmt::print(fg(fmt::color::green), "FOUND: rank_id={}\n", rank_id);

            //notificar
            for(int node=0;node<nprocs;node++) {
                fmt::print(fg(fmt::color::green), "notificando rank_{}\n", node);
                MPI_Send(&key_found,1, MPI_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }

        if(++cc % 1000==0) {
            MPI_Test(&req,&flag,&st);
            if(flag) {
                fmt::print(fg(fmt::color::red), "recv rank_{} desde el rank_{}\n", rank_id, st.MPI_SOURCE);
                break ;
            }
        }
    }

    MPI_Barrier(MPI_COMM_WORLD);

    if(rank_id==0) {
        MPI_Wait(&req,&st);

        DES_decrypt((char *)&key_found, ptr, clen,out_buffer.data() );

        char ffkey[9];
        std::memcpy(ffkey, (char *)&key_found, 8);
        ffkey[8] = 0;

        //fmt::print(fg(fmt::color::green), "FOUND: rank_id={}\n", st.MPI_SOURCE);
        fmt::print(fg(fmt::color::green), "****** key found: {}\n", ffkey);
        fmt::print(fg(fmt::color::green), "****** org text : {}\n", (char *)out_buffer.data() );
    }


    MPI_Finalize();
}
