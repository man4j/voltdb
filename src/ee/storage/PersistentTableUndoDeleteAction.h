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

#ifndef PERSISTENTTABLEUNDODELETEACTION_H_
#define PERSISTENTTABLEUNDODELETEACTION_H_

#include "common/UndoAction.h"
#include "common/TupleSchema.h"
#include "common/Pool.hpp"
#include "common/tabletuple.h"


namespace voltdb {

class PersistentTable;

class PersistentTableUndoDeleteAction: public voltdb::UndoAction {
public:
    inline PersistentTableUndoDeleteAction(char *deletedTupleData,
                                           voltdb::PersistentTable *table)
        : m_tupleData(deletedTupleData), m_table(table)
    {}

    /*
     * Undo whatever this undo action was created to undo. In this case reinsert the tuple into the table.
     */
    void undo();

    /*
     * Release any resources held by the undo action. It will not need to be undone in the future.
     * In this case free the strings associated with the tuple.
     */
    void release();
private:
    char *m_tupleData;
    PersistentTable *m_table;
};

}

#endif /* PERSISTENTTABLEUNDODELETEACTION_H_ */
