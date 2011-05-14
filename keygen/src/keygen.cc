//-----------------------------------------------------------------------------
//
//  Copyright (C) 2011 Artem Rodygin
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
#include <cstdlib>

int main ()
{
    encmq::initialize();

    return encmq::generate_rsa_keys("private.key", "public.key") ? EXIT_SUCCESS : EXIT_FAILURE;
}
