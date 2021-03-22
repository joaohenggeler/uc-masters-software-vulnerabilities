#include <stdio.h>
#include <stdlib.h>
#include "test.h"

void function_1(void)
{
	printf("Function 1\n");
}

int function_3(void);

static int function_2(int foo)
{
	return foo + function_3();
}

struct struct_1
{
	int foo;
	double bar;
};

int function_3(void)
{
	struct_1 s;
	s.foo = 1;
	s.bar = 2.0;

	return 1;
}

template<typename Type>
struct struct_2
{
	int foo;
	Type bar;
};

union union_1
{
	int foo;
	double bar;
};

class class_1
{
	public:

		class_1(int foo = 1, double bar = 2.0)
		{
			printf("Constructor 1\n");
			m_foo = foo;
			m_bar = bar;
		}

		~class_1()
		{
			printf("Destructor 1\n");
		}

		double member_function_1(int c)
		{
			return m_foo * m_bar + c;
		}

		template<typename Type>
		Type member_function_2(Type a, Type b)
		{
			return (a > b) ? (a) : (b);
		}

		bool member_function_3(int a, int b, int c);

		double operator()(double x) const
		{
			return m_bar * x + m_foo;
		}

		operator int() const
		{
			return m_foo;
		}

		explicit operator int*() const
		{
			return nullptr;
		}

	private:

		int m_foo;
		double m_bar;
};

bool class_1::member_function_3(int a, int b, int c)
{
	return (a + b + c) == 3;
}

namespace namespace_1
{
	template<typename Type>
	class class_2
	{
		public:

			class_2();
			~class_2();

			Type member_function_4(Type a, Type b)
			{
				return a + b + function_3();
			}
			
		private:

			Type m_foo;
			double m_bar;
	};

	int function_4(void)
	{
		return 4;
	}
};

int main(int argc, char const *argv[])
{
	class local_class_1
	{
		int member_function_6(void)
		{
			return 5;
		}
	};

	local_class_1 c;

	return 0;
}
