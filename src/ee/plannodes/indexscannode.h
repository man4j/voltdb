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

#ifndef HSTOREINDEXSCANNODE_H
#define HSTOREINDEXSCANNODE_H

#include "abstractscannode.h"

namespace voltdb {
/**
 *
 */
class IndexScanPlanNode : public AbstractScanPlanNode {
public:
    IndexScanPlanNode() :
        end_expression(NULL),
        lookup_type(INDEX_LOOKUP_TYPE_EQ),
        sort_direction(SORT_DIRECTION_TYPE_INVALID)
    { }
    ~IndexScanPlanNode();
    virtual PlanNodeType getPlanNodeType() const { return (PLAN_NODE_TYPE_INDEXSCAN); }

    IndexLookupType getLookupType() const { return lookup_type; }
    const std::string& getTargetIndexName() const { return target_index_name; }
    const std::vector<AbstractExpression*>& getSearchKeyExpressions() const { return searchkey_expressions; }
    AbstractExpression* getEndExpression() const { return end_expression; }
    SortDirectionType getSortDirection() const { return sort_direction; }

    std::string debugInfo(const std::string &spacer) const;

private:
    virtual void loadFromJSONObject(json_spirit::Object &obj);

    // The id of the index to reference during execution
    std::string target_index_name;
    // Logical expression that stops the scan when true for the current tuple
    AbstractExpression* end_expression;
    // Values for indexed columns (possibly just some prefix columns) at which to start scanning.
    std::vector<AbstractExpression*> searchkey_expressions;
    // Distinguish random access lookups from range scans
    IndexLookupType lookup_type;
    // Identify any output ordering relied upon by the plan -- may trigger reverse scanning.
    SortDirectionType sort_direction;
};

}

#endif
