/* This file is part of VoltDB.
 * Copyright (C) 2008-2013 VoltDB Inc.
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

package org.voltdb.plannodes;

import java.util.ArrayList;
import java.util.List;

import org.json_voltpatches.JSONException;
import org.json_voltpatches.JSONObject;
import org.json_voltpatches.JSONStringer;
import org.voltdb.catalog.Database;
import org.voltdb.expressions.AbstractExpression;
import org.voltdb.expressions.ExpressionUtil;
import org.voltdb.expressions.TupleValueExpression;
import org.voltdb.types.PlanNodeType;
import org.voltdb.types.SortDirectionType;

public class OrderByPlanNode extends AbstractPlanNode {

    public enum Members {
        SORT_EXPRESSIONS,
        SORT_DIRECTIONS;
    }

    protected List<AbstractExpression> m_sortExpressions = new ArrayList<AbstractExpression>();
    /**
     * Sort Directions
     */
    protected List<SortDirectionType> m_sortDirections = new ArrayList<SortDirectionType>();

    private boolean m_orderingByUniqueColumns = false;

    public OrderByPlanNode() {
        super();
    }

    @Override
    public PlanNodeType getPlanNodeType() {
        return PlanNodeType.ORDERBY;
    }

    @Override
    public void validate() throws Exception {
        super.validate();

        // Make sure that they have the same # of columns and directions
        if (m_sortExpressions.size() != m_sortDirections.size()) {
            throw new Exception("ERROR: PlanNode '" + toString() + "' has " +
                                "'" + m_sortExpressions.size() + "' sort expressions but " +
                                "'" + m_sortDirections.size() + "' sort directions");
        }

        // Make sure that none of the items are null
        for (int ctr = 0, cnt = m_sortExpressions.size(); ctr < cnt; ctr++) {
            if (m_sortExpressions.get(ctr) == null) {
                throw new Exception("ERROR: PlanNode '" + toString() + "' has a null " +
                                    "sort expression at position " + ctr);
            } else if (m_sortDirections.get(ctr) == null) {
                throw new Exception("ERROR: PlanNode '" + toString() + "' has a null " +
                                    "sort direction at position " + ctr);
            }
        }
    }

    /**
     * Accessor for flag marking the plan as guaranteeing an identical result/effect
     * when "replayed" against the same database state, such as during replication or CL recovery.
     * @return child's value
     */
    @Override
    public boolean isOrderDeterministic() {
        AbstractPlanNode child = m_children.get(0);
        if (child.isContentDeterministic()) {
            if (orderingByAllColumns()) {
                return true;
            }
            if (orderingByUniqueColumns()) {
                return true;
            }
            m_nondeterminismDetail = "insufficient ordering criteria.";
        } else {
            m_nondeterminismDetail = m_children.get(0).nondeterminismDetail();
        }
        return false;
    }

    private boolean orderingByAllColumns() {
        NodeSchema schema = getOutputSchema();
        for (SchemaColumn col : schema.getColumns()) {
            boolean found = false;
            for (AbstractExpression expr : m_sortExpressions) {
                if (col.getExpression().equals(expr)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    private boolean orderingByUniqueColumns() {
        return m_orderingByUniqueColumns;
    }

    public void setOrderingByUniqueColumns() {
        m_orderingByUniqueColumns = true;
    }

    /**
     * Add a sort to the order-by
     * @param sortExpr  The input expression on which to order the rows
     * @param sortDir
     */
    public void addSort(AbstractExpression sortExpr, SortDirectionType sortDir)
    {
        assert(sortExpr != null);
        // PlanNodes all need private deep copies of expressions
        // so that the resolveColumnIndexes results
        // don't get bashed by other nodes or subsequent planner runs
        try
        {
            m_sortExpressions.add((AbstractExpression) sortExpr.clone());
        }
        catch (CloneNotSupportedException e)
        {
            // This shouldn't ever happen
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        m_sortDirections.add(sortDir);
    }

    public int countOfSortExpressions() {
        return m_sortExpressions.size();
    }

    public List<AbstractExpression> getSortExpressions() {
        return m_sortExpressions;
    }

    @Override
    public void resolveColumnIndexes()
    {
        // Need to order and resolve indexes of output columns AND
        // the sort columns
        assert(m_children.size() == 1);
        m_children.get(0).resolveColumnIndexes();
        NodeSchema input_schema = m_children.get(0).getOutputSchema();
        for (SchemaColumn col : m_outputSchema.getColumns())
        {
            // At this point, they'd better all be TVEs.
            assert(col.getExpression() instanceof TupleValueExpression);
            TupleValueExpression tve = (TupleValueExpression)col.getExpression();
            int index = input_schema.getIndexOfTve(tve);
            tve.setColumnIndex(index);
        }
        m_outputSchema.sortByTveIndex();

        // Find the proper index for the sort columns.  Not quite
        // sure these should be TVEs in the long term.
        List<TupleValueExpression> sort_tves =
            new ArrayList<TupleValueExpression>();
        for (AbstractExpression sort_exps : m_sortExpressions)
        {
            sort_tves.addAll(ExpressionUtil.getTupleValueExpressions(sort_exps));
        }
        for (TupleValueExpression tve : sort_tves)
        {
            int index = input_schema.getIndexOfTve(tve);
            tve.setColumnIndex(index);
        }
    }

    @Override
    public void toJSONString(JSONStringer stringer) throws JSONException {
        super.toJSONString(stringer);
        assert (m_sortExpressions.size() == m_sortDirections.size());
        List<String> tempStrings = new ArrayList<String>();
        for (SortDirectionType sdt : m_sortDirections) {
            tempStrings.add(sdt.toString());
        }
        listStringsToJSONArray(stringer, Members.SORT_DIRECTIONS.name(), tempStrings);
        listExpressionsToJSONArray(stringer, Members.SORT_EXPRESSIONS.name(), m_sortExpressions);
    }

    @Override
    public void loadFromJSONObject( JSONObject jobj, Database db ) throws JSONException {
        helpLoadFromJSONObject(jobj, db);
        List<String> tempStrings = new ArrayList<String>();
        loadStringsFromJSONArray(jobj, tempStrings, Members.SORT_DIRECTIONS.name());
        for (String string : tempStrings) {
            m_sortDirections.add(SortDirectionType.get(string));
        }
        loadExpressionsFromJSONArray(jobj, db, m_sortExpressions, Members.SORT_EXPRESSIONS.name());
    }

    @Override
    protected String explainPlanForNode(String indent) {
        return "ORDER BY (SORT)";
    }
}
