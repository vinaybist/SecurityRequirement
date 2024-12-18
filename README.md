# SecurityRequirement
Categorization, Prioritization, and Summarization of Security Vulnerabilities or Weaknesses

# Project Description
An model leveraging SecureBERT to analyze security vulnerabilities by:

- Categorizing the type of vulnerability
- Assigning priority levels
- Providing structured analysis of security weaknesses (by using summarization model or any LLM model)

# Overview
This model is a fine-tuned version of [ehsanaghaei/SecureBERT](https://huggingface.co/ehsanaghaei/SecureBERT_Plus) 

Base Model: Fine-tuned SecureBERT for security domain understanding

Categorization: Classification of vulnerability types

Prioritization: Assignment of priority levels (HIGH/MEDIUM/LOW)

Architecture: Extending SecureBERT based model and neural network with multiple classification heads

