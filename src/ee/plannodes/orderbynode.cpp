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

#include "orderbynode.h"

#include "expressions/abstractexpression.h"

#include <boost/foreach.hpp>

#include <sstream>

using namespace std;
using namespace voltdb;

OrderByPlanNode::~OrderByPlanNode()
{
    for (int i = 0; i < m_sortExpressions.size(); i++)
    {
        delete m_sortExpressions[i];
    }
}

vector<AbstractExpression*>&
OrderByPlanNode::getSortExpressions()
{
    return m_sortExpressions;
}

void
OrderByPlanNode::setSortDirections(vector<SortDirectionType>& dirs)
{
    m_sortDirections = dirs;
}

vector<SortDirectionType>&
OrderByPlanNode::getSortDirections()
{
    return m_sortDirections;
}

const vector<SortDirectionType>&
OrderByPlanNode::getDirections() const
{
    return m_sortDirections;
}

string
OrderByPlanNode::debugInfo(const string& spacer) const
{
    ostringstream buffer;
    buffer << spacer << "SortColumns[" << m_sortExpressions.size() << "]\n";
    for (int ctr = 0, cnt = (int)m_sortExpressions.size(); ctr < cnt; ctr++)
    {
        buffer << spacer << "  [" << ctr << "] "
               << m_sortExpressions[ctr]->debug()
               << "::" << m_sortDirections[ctr] << "\n";
    }
    return buffer.str();

}

void
OrderByPlanNode::loadFromJSONObject(json_spirit::Object& obj)
{
    vector<string> sortDirectionStrings = loadStringsFromJSONArray(obj, "SORT_DIRECTIONS");
    if (sortDirectionStrings.empty()) {
        throw SerializableEEException(VOLT_EE_EXCEPTION_TYPE_EEEXCEPTION,
                                      "OrderByPlanNode::loadFromJSONObject:"
                                      " Can't find SORT_DIRECTIONS value");
    }

    BOOST_FOREACH(const std::string& sortDirectionTypeString, sortDirectionStrings) {
        m_sortDirections.push_back(stringToSortDirection(sortDirectionTypeString));
    }

    m_sortExpressions = loadExpressionsFromJSONArray(obj, "SORT_EXPRESSIONS");
    if (m_sortExpressions.empty()) {
        throw SerializableEEException(VOLT_EE_EXCEPTION_TYPE_EEEXCEPTION,
                                      "OrderByPlanNode::loadFromJSONObject:"
                                      " Can't find SORT_EXPRESSIONS value");
    }
}
