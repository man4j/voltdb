/* This file is part of VoltDB.
 * Copyright (C) 2008-2017 VoltDB Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with VoltDB.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * sysutils.hpp
 *
 * Definitions here are for common functions which access
 * system resources.
 */

#ifndef SRC_EE_COMMON_SYSUTILS_HPP_
#define SRC_EE_COMMON_SYSUTILS_HPP_

namespace voltdb {
/**
 * Write a string into cbuff, which has length cbuff_len.
 * The contents of the string are the prefix followed by
 * the output of strerror(error_no).  If this call to strerror
 * fails, return a generic, not very useful description of
 * the error_no value.
 */
inline const char *get_sys_strerror(int error_no, char cbuff[], int cbuff_len, const char *prefix){
    char uemsg[32];
    char *emsg = strerror(error_no);
    if (emsg == NULL) {
            emsg = uemsg;
            snprintf(uemsg, sizeof(uemsg), "Unknown Error %d", error_no);
    }
    memcpy(cbuff, prefix, cbuff_len);
    size_t s = strlen(cbuff);
    memcpy(cbuff + s, emsg, cbuff_len - s);
    return cbuff;
}

}
#endif /* SRC_EE_COMMON_SYSUTILS_HPP_ */
