package main

import (
	"log"

	"lckbx"
)

// ItemList is an intermediate struct that translates between the list type
// needed by Fyne and the actual list of items in the database.
type ItemList struct {
	current *lckbx.NoteItem
	ub      *lckbx.UnlockedBox
	items   []lckbx.ItemMetadata
}

func (i *ItemList) Length() int {
	return len(i.items)
}

func (i *ItemList) loadItem(id int) {
	var item lckbx.NoteItem

	iid := i.items[id].ItemId
	item, err := i.ub.GetItem(iid)
	if err != nil {
		log.Printf("Could not ItemList.loadItem: %v", err)
	}

	i.current = &item
}

func (i *ItemList) AddItem() {
	n := lckbx.NewNoteItem()
	log.Printf("Adding NoteItem: %s", n.ItemId)

	err := i.ub.AddNoteItem(n)
	if err != nil {
		log.Printf("Could not ItemList.AddItem: %v", err)
		return
	}

	i.items = i.ub.GetItemList()

	for id := range i.items {
		if i.items[id].ItemId.String() == n.ItemId.String() {
			i.loadItem(id)
			break
		}
	}
}

func (i *ItemList) DeleteItem() {
	if i.current == nil {
		return
	}
	
	log.Printf("Deleting NoteItem: %s", i.current.ItemId)

	err := i.ub.DeleteItem(i.current.ItemId)
	if err != nil {
		log.Printf("Could not ItemList.DeleteItem: %v", err)
		return
	}

	i.items = i.ub.GetItemList()

	if len(i.items) == 0 {
		i.current = nil
	} else {
		i.loadItem(0)
	}
}

func (i *ItemList) SaveItem() {
	log.Printf("Saving NoteItem: %s", i.current.ItemId)

	err := i.ub.UpdateNoteItem(*i.current)
	if err != nil {
		log.Printf("Could not ItemList.SaveItem: %v", err)
	}

	i.items = i.ub.GetItemList()
}

func (i *ItemList) Close() {
	i.ub.Lock()

	i.current = nil
	i.ub = nil
	i.items = nil
}

func NewItemList(ub *lckbx.UnlockedBox) *ItemList {
	var il ItemList

	il.ub = ub
	il.items = ub.GetItemList()

	if len(il.items) > 0 {
		il.loadItem(0)
	}

	return &il
}
