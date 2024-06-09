package com.sam.todo;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TodoService {

	@Autowired
	private TodoRepository todoRepository;


	public List<Todo> findByUsername(String username) {
		return todoRepository.findByUsername(username);
	}

	public Todo addTodo(String username , Todo todo) {
		todo.setUsername(username);
		todo.setId(null);
		return todoRepository.save(todo);
	}

	public void deleteById(int id) {
		todoRepository.deleteById(id);
	}

	public Todo findById(int id) {
		Optional<Todo> todo = todoRepository.findById(id);
		return todo.get();
	}

	public void updateTodo(Todo todo) {
		todoRepository.save(todo);
	}
}