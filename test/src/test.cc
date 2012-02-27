//-----------------------------------------------------------------------------
//
//  Copyright (C) 2010-2012 Artem Rodygin
//
//  This file is part of EncMQ.
//
//  EncMQ is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  EncMQ is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with EncMQ.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

/**
 * @author Artem Rodygin
 */

#include <encmq.h>

// Data schema.
#include <msgtest.pb.h>

// Boost C++ Libraries
#include <boost/thread.hpp>

// Standard C/C++ Libraries
#include <cstdlib>
#include <iostream>
#include <memory>

// System Libraries
#if defined(WIN32)
#include <Windows.h>
#else
#include <unistd.h>
#endif

// Namespaces in use.
using namespace std;

// Test results.
int volatile passed  = 0;
int volatile failed  = 0;
int volatile blocked = 0;

// Test marcos.
#define TEST(desc)      (cout << "[TEST #" << (passed + failed + blocked + 1) << "] " << desc << "\n")
#define TEST2(desc)     (cout << "[TEST #" << (passed + failed + blocked + 2) << "] " << desc << "\n")
#define BLOCK()         (cout << "[BLOCK]\n\n", blocked++)
#define CHECK(expr)     (expr ? (cout << "[PASS]\n\n", passed++) \
                              : (cout << "[FAIL]\n\n", failed++))

//-----------------------------------------------------------------------------

void wait ()
{
    #if defined(WIN32)
    Sleep(1000);
    #else
    usleep(1000 * 1000);
    #endif
}

//-----------------------------------------------------------------------------

void server1_main ()
{
    try
    {
        auto_ptr <encmq::server> server(new encmq::server("0.0.0.0", 5555, "private.key"));

        msgtest::request  req;
        msgtest::response rep;

        bool res = server->receive(&req);

        res = res && (req.id()    == 1         );
        res = res && (req.login() == "apushkin");

        rep.set_firstname("Alexandr");
        rep.set_lastname("Pushkin");
        rep.set_age(210);

        res = res && server->send(&rep);

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }
}

//-----------------------------------------------------------------------------

void server2_main ()
{
    try
    {
        auto_ptr <encmq::server> server(new encmq::server("0.0.0.0", 5555, "private.key"));

        google::protobuf::Message * msg = server->receive();

        bool res = (msg != NULL);

        if (msg != NULL)
        {
            res = res && (msg->GetDescriptor() == msgtest::request::descriptor());

            msgtest::request * req = dynamic_cast <msgtest::request *> (msg);

            res = res && (req->id()    == 1         );
            res = res && (req->login() == "apushkin");

            msgtest::response rep;

            rep.set_firstname("Alexandr");
            rep.set_lastname("Pushkin");
            rep.set_age(210);

            res = res && server->send(&rep);

            delete msg;
        }

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }
}

//-----------------------------------------------------------------------------

void server3_main ()
{
    try
    {
        auto_ptr <encmq::server> server(new encmq::server("0.0.0.0", 5555, "private.key"));

        google::protobuf::Message * msg = server->receive();

        bool res = (msg != NULL);

        if (msg != NULL)
        {
            res = res && (msg->GetDescriptor() == msgtest::request::descriptor());

            msgtest::request * req = dynamic_cast <msgtest::request *> (msg);

            res = res && (req->id()    == 1         );
            res = res && (req->login() == "apushkin");

            msgtest::response rep;

            rep.set_firstname("Alexandr");
            rep.set_lastname("Pushkin");
            rep.set_age(210);

            res = res && server->send(&rep);

            delete msg;
        }
    }
    catch (encmq::exception &)
    {
    }
}

//-----------------------------------------------------------------------------

void publisher1_main ()
{
    try
    {
        auto_ptr <encmq::publisher> server(new encmq::publisher("0.0.0.0", 5555));
        wait();

        msgtest::response msg;

        msg.set_firstname("Alexandr");
        msg.set_lastname("Pushkin");
        msg.set_age(210);

        bool res = server->send(&msg);

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }
}

//-----------------------------------------------------------------------------

void publisher2_main ()
{
    struct
    {
        string  topic;
        string  firstname;
        string  lastname;
        int     age;
    } test_data [3] = { {"x.y", "Alexander", "Pushkin",  210},
                        {"x.z", "Lev",       "Tolstoy",  181},
                        {"y.z", "Nickolay",  "Nekrasov", 188}
                      };

    try
    {
        auto_ptr <encmq::publisher> server(new encmq::publisher("0.0.0.0", 5555));
        wait();

        for (int i = 0; i < 3; i++)
        {
            msgtest::response msg;

            msg.set_firstname(test_data[i].firstname);
            msg.set_lastname(test_data[i].lastname);
            msg.set_age(test_data[i].age);

            server->send(&msg, test_data[i].topic.c_str());
        }
    }
    catch (encmq::exception &)
    {
    }
}

//-----------------------------------------------------------------------------

// Main routine.
int main ()
{
    encmq::initialize();
    encmq::set_loglevel(ENCMQ_FATAL_LOG_LEVEL);

    // 1 //--------------------------------------------------------------------
    try
    {
        TEST("Test RSA keys generation (fault case).");

        bool res = encmq::generate_rsa_keys("bad/private.key", "bad/public.key");

        CHECK(!res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 2 //--------------------------------------------------------------------
    try
    {
        TEST("Test RSA keys generation (success case).");

        bool res = encmq::generate_rsa_keys("private.key", "public.key");

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 3-4 //------------------------------------------------------------------
    try
    {
        TEST("Test responder (expected message mode).");
        TEST2("Test requester w/out encryption.");

        boost::thread srv_thread(server1_main);
        wait();

        msgtest::request  req;
        msgtest::response rep;

        auto_ptr <encmq::client> client(new encmq::client("127.0.0.1", 5555));

        req.set_id(1);
        req.set_login("apushkin");

        bool res = client->send(&req);
        res = res && client->receive(&rep);

        res = res && (rep.firstname() == "Alexandr");
        res = res && (rep.lastname()  == "Pushkin" );
        res = res && (rep.age()       == 210       );

        srv_thread.join();

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 5-6 //------------------------------------------------------------------
    try
    {
        TEST("Test responder (expected message mode).");
        TEST2("Test requester with encryption.");

        boost::thread srv_thread(server1_main);
        wait();

        msgtest::request  req;
        msgtest::response rep;

        auto_ptr <encmq::client> client(new encmq::client("127.0.0.1", 5555, "public.key"));

        req.set_id(1);
        req.set_login("apushkin");

        bool res = client->send(&req);
        res = res && client->receive(&rep);

        res = res && (rep.firstname() == "Alexandr");
        res = res && (rep.lastname()  == "Pushkin" );
        res = res && (rep.age()       == 210       );

        srv_thread.join();

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 7 //--------------------------------------------------------------------
    try
    {
        TEST("Test responder with non-existing RSA private key.");

        auto_ptr <encmq::server> server(new encmq::server("0.0.0.0", 5555, "bad/private.key"));

        CHECK(false);
    }
    catch (encmq::exception &e)
    {
        CHECK(e.error() == ENCMQ_ERROR_SSL_RSA);
    }

    // 8 //--------------------------------------------------------------------
    try
    {
        TEST("Test responder with invalid RSA private key.");

        auto_ptr <encmq::server> server(new encmq::server("0.0.0.0", 5555, "public.key"));

        CHECK(false);
    }
    catch (encmq::exception &e)
    {
        CHECK(e.error() == ENCMQ_ERROR_SSL_RSA);
    }

    // 9-11 //-----------------------------------------------------------------
    {
        boost::thread srv_thread(server3_main);
        wait();

        // 9 //----------------------------------------------------------------
        try
        {
            TEST("Test requester with non-existing RSA public key.");

            auto_ptr <encmq::client> client(new encmq::client("127.0.0.1", 5555, "bad/public.key"));

            CHECK(false);
        }
        catch (encmq::exception &e)
        {
            CHECK(e.error() == ENCMQ_ERROR_SSL_RSA);
        }

        // 10 //---------------------------------------------------------------
        try
        {
            TEST("Test requester with invalid RSA public key.");

            auto_ptr <encmq::client> client(new encmq::client("127.0.0.1", 5555, "private.key"));

            CHECK(false);
        }
        catch (encmq::exception &e)
        {
            CHECK(e.error() == ENCMQ_ERROR_SSL_RSA);
        }

        // 11 //---------------------------------------------------------------
        try
        {
            TEST("Test requester with wrong RSA public key.");

            bool res = encmq::generate_rsa_keys("private2.key", "public2.key");

            auto_ptr <encmq::client> client(new encmq::client("127.0.0.1", 5555, "public2.key"));

            msgtest::request req;

            req.set_id(1);
            req.set_login("apushkin");

            res = res && client->send(&req);
            wait();

            google::protobuf::Message * msg = client->receive(false);

            res = res && (msg == NULL);

            CHECK(res);
        }
        catch (encmq::exception &)
        {
            CHECK(false);
        }

        srv_thread.join();
    }

    // 12-13 //----------------------------------------------------------------
    try
    {
        TEST("Test responder (unknown message mode).");
        TEST2("Test requester in dynamic message mode (encryption is enabled).");

        boost::thread srv_thread(server2_main);
        wait();

        auto_ptr <encmq::client> client(new encmq::client("127.0.0.1", 5555, "public.key"));

        msgtest::request req;

        req.set_id(1);
        req.set_login("apushkin");

        bool res = client->send(&req);

        google::protobuf::Message * msg = client->receive();

        res = res && (msg != NULL);

        if (msg != NULL)
        {
            res = res && (msg->GetDescriptor() == msgtest::response::descriptor());

            msgtest::response * rep = dynamic_cast <msgtest::response *> (msg);

            res = res && (rep->firstname() == "Alexandr");
            res = res && (rep->lastname()  == "Pushkin" );
            res = res && (rep->age()       == 210       );

            delete msg;
        }

        srv_thread.join();

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 14-15 //----------------------------------------------------------------
    try
    {
        TEST("Test publisher.");
        TEST2("Test subscriber.");

        boost::thread pub_thread(publisher1_main);

        msgtest::response msg;

        auto_ptr <encmq::subscriber> client(new encmq::subscriber("127.0.0.1", 5555));

        client->subscribe();

        bool res = client->receive(&msg);

        res = res && (msg.firstname() == "Alexandr");
        res = res && (msg.lastname()  == "Pushkin" );
        res = res && (msg.age()       == 210       );

        pub_thread.join();

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 16 //-------------------------------------------------------------------
    try
    {
        TEST("Test subscription for all topics.");

        struct
        {
            string  firstname;
            string  lastname;
            int     age;
        } test_data [3] = { {"Alexander", "Pushkin",  210},
                            {"Lev",       "Tolstoy",  181},
                            {"Nickolay",  "Nekrasov", 188}
                          };

        boost::thread pub_thread(publisher2_main);

        auto_ptr <encmq::subscriber> client(new encmq::subscriber("127.0.0.1", 5555));

        client->subscribe();

        bool res = true;

        for (int i = 0; i < 3; i++)
        {
            msgtest::response msg;

            res = res && client->receive(&msg);

            res = res && (msg.firstname() == test_data[i].firstname);
            res = res && (msg.lastname()  == test_data[i].lastname );
            res = res && (msg.age()       == test_data[i].age      );
        }

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 17 //-------------------------------------------------------------------
    try
    {
        TEST("Test subscription for all topics with specified prefix.");

        struct
        {
            string  firstname;
            string  lastname;
            int     age;
        } test_data [2] = { {"Alexander", "Pushkin", 210},
                            {"Lev",       "Tolstoy", 181}
                          };

        boost::thread pub_thread(publisher2_main);

        auto_ptr <encmq::subscriber> client(new encmq::subscriber("127.0.0.1", 5555));

        client->subscribe("x.");

        bool res = true;

        for (int i = 0; i < 2; i++)
        {
            msgtest::response msg;

            res = res && client->receive(&msg);

            res = res && (msg.firstname() == test_data[i].firstname);
            res = res && (msg.lastname()  == test_data[i].lastname );
            res = res && (msg.age()       == test_data[i].age      );
        }

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 18 //-------------------------------------------------------------------
    try
    {
        TEST("Test subscription for particular topic.");

        struct
        {
            string  firstname;
            string  lastname;
            int     age;
        } test_data [1] = { {"Alexander", "Pushkin", 210}
                          };

        boost::thread pub_thread(publisher2_main);

        auto_ptr <encmq::subscriber> client(new encmq::subscriber("127.0.0.1", 5555));

        client->subscribe("x.y");

        bool res = true;

        for (int i = 0; i < 1; i++)
        {
            msgtest::response msg;

            res = res && client->receive(&msg);

            res = res && (msg.firstname() == test_data[i].firstname);
            res = res && (msg.lastname()  == test_data[i].lastname );
            res = res && (msg.age()       == test_data[i].age      );
        }

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    // 19 //-------------------------------------------------------------------
    try
    {
        TEST("Test subscription for several topics.");

        struct
        {
            string  firstname;
            string  lastname;
            int     age;
        } test_data [2] = { {"Lev",      "Tolstoy",  181},
                            {"Nickolay", "Nekrasov", 188}
                          };

        boost::thread pub_thread(publisher2_main);

        auto_ptr <encmq::subscriber> client(new encmq::subscriber("127.0.0.1", 5555));

        client->subscribe("x.z");
        client->subscribe("y.z");

        bool res = true;

        for (int i = 0; i < 2; i++)
        {
            msgtest::response msg;

            res = res && client->receive(&msg);

            res = res && (msg.firstname() == test_data[i].firstname);
            res = res && (msg.lastname()  == test_data[i].lastname );
            res = res && (msg.age()       == test_data[i].age      );
        }

        CHECK(res);
    }
    catch (encmq::exception &)
    {
        CHECK(false);
    }

    //-------------------------------------------------------------------------

    #define PLANNED 19

    cout << "PLANNED:  " << PLANNED << "\n";
    cout << "EXECUTED: " << (passed + failed + blocked) << "\n";
    cout << "PASSED:   " << passed  << "\n";
    cout << "FAILED:   " << failed  << "\n";
    cout << "BLOCKED:  " << blocked << "\n";

    return (passed == PLANNED && failed == 0 && blocked == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
