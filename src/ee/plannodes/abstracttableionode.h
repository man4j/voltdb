/* This file is part of VoltDB.
 * Copyright (C) 2008-2013 VoltDB Inc.
 *
 * This file contains original code and/or modifications of original code.
 * Any modifications made by VoltDB Inc. are licensed under the following
 * terms and conditions:
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
/* Copyright (C) 2008 by H-Store Project
 * Brown University
 * Massachusetts Institute of Technology
 * Yale University
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HSTORETABLEIONODE_H
#define HSTORETABLEIONODE_H

#include "abstractplannode.h"

namespace voltdb {

class Table;
class VoltDBEngine;

/**
 *
 */
class AbstractTableIOPlanNode : public AbstractPlanNode {
public:
    Table* resolveTargetTable(VoltDBEngine* engine);
    Table* getTargetTable() const;

    std::string debugInfo(const std::string &spacer) const;

protected:
    AbstractTableIOPlanNode() : m_targetTableName("NOT_SPECIFIED"), m_targetTable(NULL) {}

    void loadFromJSONObject(json_spirit::Object &obj);

    // Target Table
    // This table is different from the temp output tables managed by the executors.
    // An operation executor reads tuples from its input table(s) and applies them to the target table.
    // Its output table stores only the count of rows affected.
    // A scan executor may either read in tuples from its target table and write tuples to a temp output table,
    // OR, as an optimization for simple cases, it may identify its target table as its output table.
    // The resulting table is provided as an input table to the parent node's executor as a generic Table*
    // abstracting away the distinction between persistent table and temp table when used for read access.
    std::string m_targetTableName;
    Table* m_targetTable; // volatile
};

}

#endif
