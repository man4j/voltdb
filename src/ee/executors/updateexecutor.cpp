/* This file is part of VoltDB.
 * Copyright (C) 2008-2014 VoltDB Inc.
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

#include "updateexecutor.h"

#include "common/ValueFactory.hpp"
#include "common/ValuePeeker.hpp"
#include "common/tabletuple.h"
#include "common/FatalException.hpp"
#include "plannodes/updatenode.h"
#include "plannodes/projectionnode.h"
#include "storage/table.h"
#include "indexes/tableindex.h"
#include "storage/tableiterator.h"
#include "storage/temptable.h"
#include "storage/persistenttable.h"
#include "storage/ConstraintFailureException.h"

#include <boost/scoped_ptr.hpp>
#include <boost/foreach.hpp>

#include <cassert>

using namespace std;

namespace voltdb {

bool UpdateExecutor::p_init(AbstractPlanNode* abstract_node,
                            TempTableLimits* limits)
{
    VOLT_TRACE("init Update Executor");

    UpdatePlanNode* node = dynamic_cast<UpdatePlanNode*>(m_abstractNode);
    assert(node);
    assert(node->getInputTables().size() == 1);
    // input table should be temptable
    m_inputTable = node->getTempInputTable();
    assert(m_inputTable);

    // target table should be persistenttable
    PersistentTable*targetTable = dynamic_cast<PersistentTable*>(node->getTargetTable());
    assert(targetTable);

    setDMLCountOutputTable(limits);

    AbstractPlanNode *child = node->getChildren()[0];
    ProjectionPlanNode *proj_node = NULL;
    if (NULL == child) {
        VOLT_ERROR("Attempted to initialize update executor with NULL child");
        return false;
    }

    PlanNodeType pnt = child->getPlanNodeType();
    if (pnt == PLAN_NODE_TYPE_PROJECTION) {
        proj_node = dynamic_cast<ProjectionPlanNode*>(child);
    } else if (pnt == PLAN_NODE_TYPE_SEQSCAN ||
            pnt == PLAN_NODE_TYPE_INDEXSCAN) {
        proj_node = dynamic_cast<ProjectionPlanNode*>(child->getInlinePlanNode(PLAN_NODE_TYPE_PROJECTION));
        assert(NULL != proj_node);
    }

    vector<string> output_column_names = proj_node->getOutputColumnNames();
    const vector<string> &targettable_column_names = targetTable->getColumnNames();

    /*
     * The first output column is the tuple address expression and it isn't part of our output so we skip
     * it when generating the map from input columns to the target table columns.
     */
    for (int ii = 1; ii < output_column_names.size(); ii++) {
        for (int jj=0; jj < targettable_column_names.size(); ++jj) {
            if (targettable_column_names[jj].compare(output_column_names[ii]) == 0) {
                m_inputTargetMap.push_back(pair<int,int>(ii, jj));
                break;
            }
        }
    }

    assert(m_inputTargetMap.size() == (output_column_names.size() - 1));
    m_inputTargetMapSize = (int)m_inputTargetMap.size();

    // for target table related info.
    m_partitionColumn = targetTable->partitionColumn();
    m_partitionColumnIsString = false;
    if (m_partitionColumn != -1) {
        if (targetTable->schema()->columnType(m_partitionColumn) == VALUE_TYPE_VARCHAR) {
            m_partitionColumnIsString = true;
        }
    }

    return true;
}

bool UpdateExecutor::p_execute(const NValueArray &params) {
    assert(m_inputTable);

    // target table should be persistenttable
    UpdatePlanNode* node = dynamic_cast<UpdatePlanNode*>(m_abstractNode);
    assert(node);
    PersistentTable* targetTable = dynamic_cast<PersistentTable*>(node->getTargetTable());
    assert(targetTable);
    TableTuple targetTuple = TableTuple(targetTable->schema());

    VOLT_TRACE("INPUT TABLE: %s\n", m_inputTable->debug().c_str());
    VOLT_TRACE("TARGET TABLE - BEFORE: %s\n", targetTable->debug().c_str());

    // determine which indices are updated by this executor
    // iterate through all target table indices and see if they contain
    // columns mutated by this executor
    std::vector<TableIndex*> indexesToUpdate;
    const std::vector<TableIndex*>& allIndexes = targetTable->allIndexes();
    BOOST_FOREACH(TableIndex *index, allIndexes) {
        bool indexKeyUpdated = false;
        BOOST_FOREACH(int colIndex, index->getColumnIndices()) {
            std::pair<int, int> updateColInfo; // needs to be here because of macro failure
            BOOST_FOREACH(updateColInfo, m_inputTargetMap) {
                if (updateColInfo.second == colIndex) {
                    indexKeyUpdated = true;
                    break;
                }
            }
            if (indexKeyUpdated) break;
        }
        if (indexKeyUpdated) {
            indexesToUpdate.push_back(index);
        }
    }

    TableTuple inputTuple = m_inputTable->tempTuple();
    TableIterator input_iterator = m_inputTable->iterator();
    while (input_iterator.next(inputTuple)) {
        //
        // OPTIMIZATION: Single-Sited Query Plans
        // If our beloved UpdatePlanNode is apart of a single-site query plan,
        // then the first column in the input table will be the address of a
        // tuple on the target table that we will want to update. This saves us
        // the trouble of having to do an index lookup
        //
        void *target_address = inputTuple.getNValue(0).castAsAddress();
        targetTuple.move(target_address);

        // Loop through INPUT_COL_IDX->TARGET_COL_IDX mapping and only update
        // the values that we need to. The key thing to note here is that we
        // grab a temp tuple that is a copy of the target tuple (i.e., the tuple
        // we want to update). This insures that if the input tuple is somehow
        // bringing garbage with it, we're only going to copy what we really
        // need to into the target tuple.
        //
        TableTuple &tempTuple = targetTable->getTempTupleInlined(targetTuple);
        for (int map_ctr = 0; map_ctr < m_inputTargetMapSize; map_ctr++) {
            tempTuple.setNValue(m_inputTargetMap[map_ctr].second,
                                inputTuple.getNValue(m_inputTargetMap[map_ctr].first));
        }

        // if there is a partition column for the target table
        if (m_partitionColumn != -1) {
            // check for partition problems
            // get the value for the partition column
            NValue value = tempTuple.getNValue(m_partitionColumn);
            bool isLocal = m_engine->isLocalSite(value);

            // if it doesn't map to this site
            if (!isLocal) {
                throw ConstraintFailureException(
                         dynamic_cast<PersistentTable*>(targetTable),
                         tempTuple,
                         "An update to a partitioning column triggered a partitioning error. "
                         "Updating a partitioning column is not supported. Try delete followed by insert.");
            }
        }

        targetTable->updateTupleWithSpecificIndexes(targetTuple, tempTuple, indexesToUpdate);
    }

    TableTuple& count_tuple = m_tmpOutputTable->tempTuple();
    count_tuple.setNValue(0, ValueFactory::getBigIntValue(m_inputTable->tempTableTupleCount()));
    // try to put the tuple into the output table
    m_tmpOutputTable->insertTempTuple(count_tuple);

    VOLT_TRACE("TARGET TABLE - AFTER: %s\n", targetTable->debug().c_str());
    // TODO lets output result table here, not in result executor. same thing in
    // delete/insert

    // add to the planfragments count of modified tuples
    m_engine->m_tuplesModified += m_inputTable->tempTableTupleCount();

    return true;
}

} // namespace voltdb
